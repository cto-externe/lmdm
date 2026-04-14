.PHONY: help build test test-unit test-integration lint proto clean docker-up docker-down

GO ?= go
GOLANGCI_LINT ?= golangci-lint
BUF ?= buf

help:
	@echo "Cibles disponibles :"
	@echo "  build              - compile le serveur"
	@echo "  test               - lance tous les tests"
	@echo "  test-unit          - tests unitaires seulement"
	@echo "  test-integration   - tests d'intégration (requiert Docker)"
	@echo "  lint               - golangci-lint + buf lint"
	@echo "  proto              - régénère le code Go depuis les protos"
	@echo "  docker-up          - démarre postgres + nats + garage"
	@echo "  docker-down        - arrête la stack dev"
	@echo "  clean              - supprime les artefacts de build"

build:
	$(GO) build -o bin/lmdm-server ./cmd/lmdm-server

test:
	$(GO) test ./...

test-unit:
	$(GO) test -short ./...

test-integration:
	$(GO) test -run Integration ./...

lint:
	$(GOLANGCI_LINT) run ./...
	$(BUF) lint

proto:
	$(BUF) generate

docker-up:
	docker compose up -d

docker-down:
	docker compose down

clean:
	rm -rf bin/ dist/ coverage.out coverage.html
