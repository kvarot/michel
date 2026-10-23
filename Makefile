.PHONY: build web test lint

# The front is built (and embedded by go build) only where npm exists; without
# it the binary still builds and michel serve shows a short text page.
ifneq ($(shell command -v npm 2>/dev/null),)
build: web
endif

build:
	go build -o bin/michel ./cmd/michel

web:
	cd web && npm ci && npm run build

test:
	go test ./...

# All outbound HTTP must go through internal/egress (also run by go test ./...).
lint:
	go test ./internal/egress/ -run TestNoDirectHTTPOutsideEgress
