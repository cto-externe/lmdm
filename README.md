# LMDM — Linux MDM

Outil souverain de gestion de parc Linux pour collectivités et administrations.

**État actuel** : le serveur gère l'enrôlement d'agents avec crypto post-quantique hybride (Ed25519 + ML-DSA-65), collecte l'inventaire matériel/logiciel/réseau, applique des profils de sécurité (policy engine avec 4 types d'actions + rollback), détecte les mises à jour disponibles (Debian apt + RHEL dnf), et expose une API REST pour l'administration. 7 tests d'intégration end-to-end valident le pipeline complet.

## Prérequis

- **Go 1.26+** (toolchain épinglée à 1.26.0 dans `go.mod`)
- Docker + Docker Compose
- `buf` CLI — <https://buf.build/docs/installation>
- `golangci-lint` v2 — <https://golangci-lint.run/welcome/install/>
- `protoc-gen-go` + `protoc-gen-go-grpc` (pour régénérer les protos, via `go install`)

## Démarrage rapide

```bash
make docker-up     # postgres, nats, garage
make build         # compile tous les binaires dans bin/
make test-unit     # tests unitaires (rapides, pas de Docker)
```

### Initialiser Garage (une seule fois)

```bash
NODE_ID=$(docker compose exec -T garage /garage node id -q | cut -d@ -f1)
docker compose exec -T garage /garage layout assign -z dc1 -c 1G "$NODE_ID"
docker compose exec -T garage /garage layout apply --version 1

docker compose exec -T garage /garage key create lmdm-dev-key
# Notez les valeurs `Key ID` et `Secret key` retournées.

docker compose exec -T garage /garage bucket create lmdm-packages
docker compose exec -T garage /garage bucket allow \
    --read --write --owner lmdm-packages --key lmdm-dev-key
```

### Démarrer le serveur

```bash
export LMDM_S3_ACCESS_KEY=<Key ID>
export LMDM_S3_SECRET_KEY=<Secret key>
go run ./cmd/lmdm-server
```

Le serveur expose :
- **`http://localhost:8080/healthz`** — health check (db + nats + s3)
- **`http://localhost:8080/api/v1/...`** — API REST admin (voir ci-dessous)
- **`localhost:50051`** — gRPC (EnrollmentService)

### Enrôler un agent

**1. Générer un token** (via CLI ou API) :

```bash
# Via CLI
go run ./cmd/lmdm-token -description="poste-test" -ttl=24h -max-uses=1

# Via API REST
curl -s -X POST http://localhost:8080/api/v1/tokens \
  -H 'Content-Type: application/json' \
  -d '{"description":"poste-test","max_uses":1,"ttl_seconds":86400}' | jq
```

**2. Enrôler l'agent** (côté poste client) :

```bash
go run ./cmd/lmdm-agent enroll \
    --token=<plaintext-du-token> \
    --server=localhost:50051 \
    --data-dir=/tmp/agent-dev
```

**3. Lancer l'agent** :

```bash
go run ./cmd/lmdm-agent run \
    --data-dir=/tmp/agent-dev \
    --nats-url=nats://localhost:4222 \
    --interval=30s \
    --inventory-interval=1h \
    --compliance-interval=1h \
    --patch-interval=6h
```

L'agent démarre 4 boucles concurrentes : heartbeat (30s), inventaire (1h), compliance drift (1h), détection patches (6h). Il écoute aussi les commandes serveur (profils, patches) via NATS.

## API REST

12 endpoints sur `http://localhost:8080/api/v1/` :

```bash
# Devices
curl -s http://localhost:8080/api/v1/devices | jq                     # lister (filtres: status, type, hostname)
curl -s http://localhost:8080/api/v1/devices/<id> | jq                # détail
curl -s http://localhost:8080/api/v1/devices/<id>/inventory | jq      # inventaire HW/SW/réseau (JSONB)
curl -s http://localhost:8080/api/v1/devices/<id>/compliance | jq     # statut conformité
curl -s http://localhost:8080/api/v1/devices/<id>/updates | jq        # mises à jour disponibles

# Patches
curl -s -X POST http://localhost:8080/api/v1/devices/<id>/updates/apply \
  -d '{"security_only":true}' | jq                                    # appliquer les patches

# Profils
curl -s http://localhost:8080/api/v1/profiles | jq                    # lister
curl -s http://localhost:8080/api/v1/profiles/<id> | jq               # détail + YAML
curl -s -X POST http://localhost:8080/api/v1/profiles \
  --data-binary @anssi-minimal.yml | jq                               # créer (signé PQ)
curl -s -X POST http://localhost:8080/api/v1/profiles/<id>/assign/<device-id> | jq  # assigner + push NATS

# Tokens
curl -s http://localhost:8080/api/v1/tokens | jq                      # lister
curl -s -X POST http://localhost:8080/api/v1/tokens \
  -d '{"description":"test","max_uses":5,"ttl_seconds":86400}' | jq   # créer
```

### Health monitoring

LMDM remonte toutes les 6 heures la santé matérielle de chaque poste :

- **Disques** — SMART (SATA) et NVMe smart-log (wear, errors, température)
- **Batterie** — capacité, cycles, % santé via sysfs
- **Températures** — CPU/GPU via hwmon
- **Firmware** — mises à jour disponibles via fwupd/LVFS

Score global GREEN / ORANGE / RED calculé côté agent et remonté au serveur. Consultable via `GET /api/v1/devices/{id}/health`.

Voir [docs/fr/health.md](docs/fr/health.md) pour les seuils détaillés et le format de réponse.

### Déploiements canary et rollback

Les profils sont poussés en deux temps : d'abord sur un device canary, puis sur le reste du groupe après validation (manuelle, semi-auto avec timer 30 min, ou auto). En cas d'échec du canary, le reste du parc n'est jamais touché. En cas d'ack NATS manquant post-application, l'agent rollback automatiquement.

- Machine à états à 9 statuts persistée en DB
- Mode `manual` / `semi_auto` / `auto` configurable par déploiement
- Seuil d'abort 10% par défaut pendant le rollout
- Health checks post-application (4 built-in + 5 types custom)
- Agent persiste le pending deployment en BoltDB (résilient aux crashes)
- Watchdog au démarrage agent : rollback automatique des pending stale

Voir [docs/fr/deployments.md](docs/fr/deployments.md) pour le guide opérationnel complet.

### mTLS transport et PKI X.509

Tous les canaux (gRPC, NATS, REST) sont chiffrés et mutuellement authentifiés via une PKI X.509 :

- CA auto-générée par `lmdm-keygen` (ou externe via `LMDM_CA_*`)
- Certs agents délivrés à l'enrôlement via CSR — la clé privée ne quitte jamais le poste
- TLS 1.3 avec échange de clés post-quantique hybride (X25519MLKEM768)
- Renouvellement automatique 30 jours avant expiration
- Révocation immédiate via `POST /api/v1/devices/{id}/revoke` + broadcast NATS
- Défense en profondeur : `SignedAgentCert` proto PQ-hybride (Ed25519 + ML-DSA) en parallèle du X.509

Voir [docs/fr/mtls.md](docs/fr/mtls.md) pour le guide complet.

### Authentification console et RBAC

LMDM inclut une authentification console avec MFA TOTP obligatoire :

- Login/password (argon2id) + TOTP (6 chiffres, AES-256-GCM au repos)
- JWT ES256 access token (15 min) + refresh opaque avec rotation (7 j)
- 3 rôles : **Admin** (tout), **Operator** (actions terrain), **Viewer** (lecture seule)
- Account lockout après 5 échecs, rate limit IP
- Audit trail complet : events auth + mutations API

Voir [docs/fr/auth.md](docs/fr/auth.md) pour le guide opérationnel complet.

**Bootstrap rapide** :

```bash
make keys
export LMDM_PG_DSN='postgres://lmdm:lmdm@localhost:5432/lmdm?sslmode=disable'
export LMDM_ENC_KEY_PATH=deploy/secrets/enc-key.b64
go run ./cmd/lmdm-user create-admin --email admin@exemple.fr
```

### Profils ANSSI-BP-028

LMDM livre 4 profils YAML alignés sur le guide [ANSSI-BP-028 v2.0](https://messervices.cyber.gouv.fr/documents-guides/fr_np_linux_configuration-v2.0.pdf) :

- `profiles/anssi/anssi-minimal.yml` — durcissement de base (niveau M)
- `profiles/anssi/anssi-intermediaire.yml` — recommandé sur la plupart des systèmes (M+I)
- `profiles/anssi/anssi-renforce.yml` — systèmes à fort besoin de sécurité (M+I+R)
- `profiles/anssi/anssi-eleve.yml` — ops avec ressources dédiées (M+I+R+E)

Chaque règle porte un commentaire `# ANSSI R{NN} — {titre}` pour faciliter l'audit RSSI.

Trois nouveaux action types accompagnent les profils :

- `nftables_rules` — pare-feu avec validation `nft -c` avant reload
- `kernel_module_blacklist` — empêche le chargement de modules (cramfs, usb_storage, etc.)
- `file_template` — Go `text/template` avec variables device (`.Hostname`, `.DeviceID`, `.TenantID`)

Un hook optionnel `post_apply_command` sur `file_content` / `package_ensure` / `file_template` permet de déclencher une commande shell après succès de l'Apply (ex : `update-grub`, `apparmor_parser -r`). Un exit non-nul déclenche le rollback.

Guide opérateur : [docs/fr/anssi.md](docs/fr/anssi.md). Matrice de couverture des 80 recommandations : [docs/fr/anssi-coverage.md](docs/fr/anssi-coverage.md). Smoke test : `sudo ./scripts/anssi-check.sh minimal`.

## Structure

- `proto/lmdm/v1/` — définitions protobuf (API v1)
- `gen/go/lmdm/v1/` — code Go généré (commité)
- `internal/` — code applicatif
  - `pqhybrid/` — crypto post-quantique hybride (Ed25519+ML-DSA, X25519+ML-KEM, BLAKE3)
  - `db/` — accès PostgreSQL (pgx + 9 migrations embarquées)
  - `natsbus/`, `agentbus/` — wrappers NATS (serveur et agent)
  - `objectstore/` — client S3/Garage
  - `serverkey/`, `agentkey/` — keystores hybrides sur disque
  - `tokens/`, `devices/`, `profiles/` — repositories DB tenant-scoped
  - `identity/` — signature des agent identity certificates
  - `policy/` — moteur de politiques (Action interface, 4 types, executor ordonné, snapshot, rollback, YAML parser)
  - `distro/` — abstraction multi-distro (PatchManager : Debian apt, RHEL dnf, NixOS stub)
  - `agentcert/`, `agentenroll/`, `agentstatus/`, `agentrunner/` — stack agent (heartbeat)
  - `agentinventory/`, `agentinventoryrunner/` — collecte inventaire HW/SW/réseau
  - `agentpolicy/` — réception profils, drift detection, RemoveProfileCommand
  - `agentpatchrunner/` — détection périodique des mises à jour
  - `grpcservices/` — handlers gRPC serveur (EnrollmentService)
  - `statusingester/`, `inventoryingester/`, `complianceingester/`, `patchingester/` — consumers JetStream
  - `api/` — handlers REST API (12 endpoints)
  - `server/` — orchestration HTTP + gRPC + graceful shutdown
  - `config/` — chargement config depuis l'environnement
- `cmd/` — binaires
  - `lmdm-server` — serveur central (gRPC + REST + ingesters)
  - `lmdm-agent` — agent Linux (sous-commandes `enroll`, `run`)
  - `lmdm-token` — CLI admin pour émettre des tokens d'enrôlement
  - `lmdm-profile` — CLI admin pour créer/assigner des profils
- `deploy/` — configs de déploiement (ex: `garage.toml` pour le dev)

## Tests

```bash
make test-unit         # rapide, pas de Docker
make test-integration  # utilise testcontainers (postgres + nats)
make lint              # golangci-lint v2 + buf lint
```

7 tests d'intégration e2e avec `testcontainers-go` (postgres:16 + nats:2.10 réels) :

1. **Healthz** — healthcheck db+nats+s3
2. **Enrollment** — token → enroll → cert signé PQ
3. **Heartbeat** — agent → NATS → devices.last_seen
4. **Inventory** — collecte HW/SW → JSONB en DB
5. **Policy** — profil signé → apply → compliance report
6. **REST API** — create token → enroll → list devices
7. **Patches** — PatchReport → ingester → REST API updates

## Distributions supportées

| Famille | Gestionnaire | Inventaire | Patch Management |
|---|---|---|---|
| **Debian / Ubuntu / Mint** | apt/dpkg | ✅ complet | ✅ detect + apply |
| **RHEL / Alma / Rocky / Fedora** | dnf/rpm | ❌ (v0.2) | ✅ detect + apply |
| **NixOS** | nix | ❌ (v0.3) | stub (déclaratif → profils) |

## Licence

Ce projet est distribué sous **EUPL v1.2** (European Union Public Licence) — voir [LICENSE](LICENSE) et [LICENSE.fr](LICENSE.fr).

```
// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe
```

Copyright © 2026 CTO Externe.
