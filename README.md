# LMDM — Linux MDM

Outil souverain de gestion de parc Linux pour collectivités et administrations.

Voir `ARCHITECTURE_SPEC_V1.md` pour la spécification complète.

## Prérequis

- Go 1.24+
- Docker + Docker Compose
- `buf` CLI (installation : <https://buf.build/docs/installation>)
- `golangci-lint` (installation : <https://golangci-lint.run/welcome/install/>)

## Démarrage rapide

```bash
make docker-up        # postgres, nats, garage
make proto            # génère le code Go depuis les protos
make build            # compile le serveur
make test             # lance les tests
./bin/lmdm-server     # démarre le serveur
```

Le serveur expose `http://localhost:8080/healthz`.

### Initialiser Garage (une seule fois après `make docker-up`)

Garage exige une init manuelle (assignation de layout, création de clés, création du bucket) :

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

Puis exportez les clés avant de démarrer le serveur :

```bash
export LMDM_S3_ACCESS_KEY=<Key ID>
export LMDM_S3_SECRET_KEY=<Secret key>
go run ./cmd/lmdm-server
```

Testez :

```bash
curl -s http://localhost:8080/healthz | jq
# => {"status":"ok","checks":{"db":"ok","nats":"ok","s3":"ok"}}
```

## Structure

- `proto/lmdm/v1/` — définitions protobuf
- `gen/go/lmdm/v1/` — code Go généré (commité)
- `internal/` — code applicatif (non exposé en tant que bibliothèque)
- `cmd/lmdm-server/` — entrypoint serveur
- `docs/` — documentation (incluant les plans de développement)

## Tests

```bash
make test-unit         # rapide, pas de Docker
make test-integration  # utilise testcontainers
make lint              # golangci-lint + buf lint
```

## Développement

Voir [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

## Plans

Les plans d'implémentation sont dans [docs/superpowers/plans/](docs/superpowers/plans/).
