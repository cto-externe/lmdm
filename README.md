# LMDM — Linux MDM

Outil souverain de gestion de parc Linux pour collectivités et administrations.

**État actuel** : foundations + enrollment + heartbeat loop. Le serveur reçoit l'enrôlement d'agents, signe un certificat hybride post-quantique (Ed25519 + ML-DSA-65), et ingère les heartbeats publiés par les agents sur NATS JetStream.

## Prérequis

- **Go 1.26+** (toolchain épinglée à 1.26.0 dans `go.mod`)
- Docker + Docker Compose
- `buf` CLI — <https://buf.build/docs/installation>
- `golangci-lint` v2 — <https://golangci-lint.run/welcome/install/>
- `protoc-gen-go` + `protoc-gen-go-grpc` (pour régénérer les protos localement, via `go install` standard)

## Démarrage rapide

```bash
make docker-up     # postgres, nats, garage
make build         # compile tous les binaires dans bin/
make test-unit     # tests unitaires (rapides, pas de Docker)
```

### Initialiser Garage (une seule fois)

Garage requiert une init manuelle (assignation de layout, création de clés, création du bucket) :

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
- **`localhost:50051`** — gRPC (EnrollmentService)

```bash
curl -s http://localhost:8080/healthz | jq
# => {"status":"ok","checks":{"db":"ok","nats":"ok","s3":"ok"}}
```

### Enrôler un agent

Le projet distribue trois binaires. Une fois le serveur démarré :

**1. Générer un token d'enrôlement** (côté admin) :

```bash
go run ./cmd/lmdm-token -description="poste-test" -ttl=24h -max-uses=1
# Affiche le plaintext du token UNE SEULE FOIS.
```

**2. Enrôler l'agent** (côté poste client) :

```bash
go run ./cmd/lmdm-agent enroll \
    --token=<plaintext-du-token> \
    --server=localhost:50051 \
    --data-dir=/tmp/agent-dev
# Persiste la keypair hybride (agent.key, 0600) et le cert signé (agent.identity, 0600).
```

**3. Lancer la boucle heartbeat** :

```bash
go run ./cmd/lmdm-agent run \
    --data-dir=/tmp/agent-dev \
    --nats-url=nats://localhost:4222 \
    --interval=5s
# Publie un Heartbeat toutes les 5s sur fleet.agent.<device_id>.status.
```

Le serveur ingère et met à jour `devices.last_seen` + `devices.agent_version` dans PostgreSQL. Vérifier :

```bash
docker compose exec -T postgres psql -U lmdm -c \
    "SELECT hostname, agent_version, last_seen FROM devices;"
```

## Structure

- `proto/lmdm/v1/` — définitions protobuf (API v1)
- `gen/go/lmdm/v1/` — code Go généré (commité)
- `internal/` — code applicatif
  - `pqhybrid/` — crypto post-quantique hybride (Ed25519+ML-DSA, X25519+ML-KEM, BLAKE3)
  - `db/` — accès PostgreSQL (pgx + migrations embarquées)
  - `natsbus/`, `agentbus/` — wrappers NATS (serveur et agent)
  - `objectstore/` — client S3/Garage
  - `serverkey/`, `agentkey/` — keystores hybrides sur disque
  - `tokens/`, `devices/` — repositories DB tenant-scoped
  - `identity/` — signature des agent identity certificates
  - `agentcert/`, `agentenroll/`, `agentstatus/`, `agentrunner/` — stack côté agent
  - `grpcservices/` — handlers gRPC serveur (EnrollmentService)
  - `statusingester/` — consumer JetStream qui met à jour `devices.last_seen`
  - `server/` — orchestration HTTP + gRPC + graceful shutdown
  - `config/` — chargement config depuis l'environnement
- `cmd/` — binaires
  - `lmdm-server` — serveur central
  - `lmdm-agent` — agent Linux (sous-commandes `enroll`, `run`)
  - `lmdm-token` — CLI admin pour émettre des tokens d'enrôlement
- `deploy/` — configs de déploiement (ex: `garage.toml` pour le dev)

## Tests

```bash
make test-unit         # rapide, pas de Docker
make test-integration  # utilise testcontainers (postgres + nats)
make lint              # golangci-lint v2 + buf lint
```

Les tests d'intégration tournent avec `testcontainers-go` et démarrent des containers réels (postgres:16-alpine, nats:2.10-alpine) — pas de mocks. Un test e2e (`TestIntegrationHeartbeatLoop`) valide le flow complet : token → enroll → heartbeat → DB mise à jour.

## Licence

Ce projet est distribué sous **EUPL v1.2** (European Union Public Licence) — voir [LICENSE](LICENSE) et [LICENSE.fr](LICENSE.fr).

Chaque fichier source porte les en-têtes SPDX canoniques :

```
// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe
```

Copyright © 2026 CTO Externe.
