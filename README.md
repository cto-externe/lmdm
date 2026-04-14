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
