.PHONY: help build test test-unit test-integration lint proto clean docker-up docker-down keys tailwind templ webui-build install-tailwind install-templ tailwind-watch

GO ?= go
GOLANGCI_LINT ?= golangci-lint
BUF ?= buf
TAILWIND ?= bin/tailwindcss
TEMPL    ?= $(shell go env GOPATH)/bin/templ

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

build: webui-build
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

keys:
	mkdir -p deploy/secrets
	$(GO) run ./cmd/lmdm-keygen --out deploy/secrets

install-tailwind:
	./scripts/install-tailwind.sh

install-templ:
	go install github.com/a-h/templ/cmd/templ@latest

tailwind:
	$(TAILWIND) -i internal/webui/assets/tailwind.css -o internal/webui/assets/app.css --minify

tailwind-watch:
	$(TAILWIND) -i internal/webui/assets/tailwind.css -o internal/webui/assets/app.css --watch

templ:
	$(TEMPL) generate ./internal/webui/...

webui-build: templ tailwind
	@echo "WebUI assets regenerated"
