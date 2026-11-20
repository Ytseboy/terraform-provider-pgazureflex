BINARY   := terraform-provider-pgazureflex
VERSION  := 0.1.0
OS_ARCH  := $(shell go env GOOS)_$(shell go env GOARCH)
HOSTNAME := registry.terraform.io
NAMESPACE := ytseboy
NAME     := pgazureflex

.PHONY: build test test-integration verify-lean vet fmt install clean

build:
	go build -ldflags="-X main.version=$(VERSION)" -o $(BINARY) .

vet:
	go vet ./...

fmt:
	gofmt -s -w .

test:
	go test -v -race ./...

test-integration:
	@echo "Building PostgreSQL 16 Docker image with pgaadauth security label provider + azure.extensions GUC..."
	@docker build -q -t pgazureflex-sim-pg16 -f test/docker/Dockerfile .
	@echo "Starting PostgreSQL 16 Azure Flexible Server simulation container..."
	@docker rm -f pgazureflex-test-pg >/dev/null 2>&1 || true
	@docker run -d --name pgazureflex-test-pg \
		-e POSTGRES_PASSWORD=postgres \
		-p 15432:5432 \
		pgazureflex-sim-pg16 \
		-c shared_preload_libraries=pgaadauth_mock \
		-c wal_level=logical \
		-c azure.extensions=PGCRYPTO,UUID-OSSP,VECTOR
	@until docker exec pgazureflex-test-pg pg_isready -U postgres >/dev/null 2>&1; do sleep 0.5; done
	@sleep 1
	PGAZUREFLEX_TEST_HOST=127.0.0.1 \
	PGAZUREFLEX_TEST_PORT=15432 \
	PGAZUREFLEX_TEST_USER=flexadmin \
	PGAZUREFLEX_TEST_PASSWORD=flexadmin-secret \
	PGAZUREFLEX_TEST_SUPERUSER=postgres \
	PGAZUREFLEX_TEST_SUPERUSER_PASSWORD=postgres \
	PGAZUREFLEX_TEST_SSLMODE=disable \
	go test -v -race ./internal/provider -run 'TestAzureFlexibleServerEndToEnd|TestEntraRoleMappingSecurityLabelEndToEnd|TestMockAzureEntraAuthEndToEnd|TestLifecyclePlanIdempotencyImportDeleteEndToEnd'; \
	STATUS=$$?; \
	docker rm -f pgazureflex-test-pg >/dev/null 2>&1 || true; \
	exit $$STATUS

install: build
	mkdir -p ~/.terraform.d/plugins/$(HOSTNAME)/$(NAMESPACE)/$(NAME)/$(VERSION)/$(OS_ARCH)
	cp $(BINARY) ~/.terraform.d/plugins/$(HOSTNAME)/$(NAMESPACE)/$(NAME)/$(VERSION)/$(OS_ARCH)/$(BINARY)_v$(VERSION)

verify-lean:
	@if command -v lake >/dev/null 2>&1; then \
		echo "Running Lean 4 formal verification via local lake..."; \
		cd formal && lake build; \
	else \
		echo "Building Lean 4 verification Docker image (v4.16.0)..."; \
		docker build -q -t pgazureflex-lean4 -f formal/Dockerfile .; \
		echo "Running Lean 4 kernel proof verification (lake build)..."; \
		docker run --rm -v "$(CURDIR)/formal:/workspace/formal" pgazureflex-lean4 lake build; \
	fi

clean:
	rm -f $(BINARY)
