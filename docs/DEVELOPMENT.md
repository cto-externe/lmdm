# Développement LMDM

## Philosophie

- **TDD** : les tests d'abord, l'implémentation ensuite, commits fréquents.
- **DRY** : factoriser dès qu'un pattern apparaît 3 fois, pas avant.
- **YAGNI** : pas de fonctionnalité sans justification immédiate. Pas d'abstraction spéculative.
- **No placeholders** : pas de `TODO`, `FIXME`, ou code mort dans les commits de fonctionnalités.

## Structure du code

- `proto/lmdm/v1/` — définitions protobuf canoniques. Une modification requiert `buf lint` et `buf breaking`.
- `gen/go/lmdm/v1/` — code généré, commité (pas besoin d'exécuter `buf generate` pour compiler).
- `internal/pqhybrid/` — unique point d'entrée pour la cryptographie. Aucun autre package ne doit importer `crypto/ed25519`, `crypto/mlkem` ou `circl`.
- `internal/db/`, `internal/natsbus/`, `internal/objectstore/` — accès infrastructure. Sans logique métier.
- `internal/server/` — orchestration HTTP + gRPC.
- `cmd/lmdm-server/` — entrypoint.

## Tests

Trois niveaux :

1. **Unitaires** (`go test -short ./...`) — pas de Docker, rapides, exécutés sur chaque push.
2. **Intégration** (`go test -run Integration ./...`) — testcontainers Docker, testent les vraies interactions DB/NATS/S3.
3. **E2E** (à venir dans des plans ultérieurs) — VMs multi-distro.

Tout nouveau code doit avoir un test. Les tests d'intégration vivent dans le même package que le code testé, distingués par le préfixe `TestIntegration`.

## Cryptographie

Toute modification du package `pqhybrid` doit :

- Conserver les tests de tamper detection (Verify rejette les manipulations).
- Exécuter le fuzzing pendant au moins 60s avant commit (`go test -fuzz=. -fuzztime=60s ./internal/pqhybrid/...`).
- Ne jamais exposer de clé privée en clair en dehors du package.

## Migrations

- Ajouter `000N_nom.up.sql` et `000N_nom.down.sql` sous `internal/db/migrations/`.
- Chaque nouvelle table tenant-scoped doit :
  - Avoir une colonne `tenant_id UUID NOT NULL REFERENCES tenants(id)`.
  - Activer `ROW LEVEL SECURITY`.
  - Définir une policy `USING (tenant_id = lmdm_current_tenant())`.
- Les tests d'isolation RLS sont obligatoires pour toute nouvelle table.

## Commits

- Format : `type(scope): description` (feat, fix, chore, test, docs, ci, refactor).
- Pas de signature Claude dans les messages.
- Pas de `git push` automatique.
