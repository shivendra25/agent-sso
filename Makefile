.PHONY: all build test fmt vet docs-lint ci tidy

all: build

GO ?= go
BINS := aidp gateway admin

build:
	@for bin in $(BINS); do \
		echo "→ building $$bin"; \
		$(GO) build -o bin/$$bin ./cmd/$$bin; \
	done

test:
	$(GO) test ./... -race -cover

fmt:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...

tidy:
	$(GO) mod tidy

docs-lint:
	@if command -v markdownlint >/dev/null 2>&1; then \
		markdownlint docs/ README.md; \
	else \
		echo "markdownlint not installed, skipping"; \
	fi

ci: fmt vet test docs-lint
	@echo "✓ CI passed"