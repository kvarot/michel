.PHONY: build test lint

build:
	go build -o bin/michel ./cmd/michel

test:
	go test ./...

# All outbound HTTP must go through internal/egress.
lint:
	@if grep -rnE --include='*.go' --exclude-dir=egress 'http\.DefaultClient|http\.Get\(|http\.Post\(' . ; then \
		echo "lint: use internal/egress for HTTP calls"; exit 1; \
	fi
