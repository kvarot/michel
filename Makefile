.PHONY: build test lint

build:
	go build -o bin/michel ./cmd/michel

test:
	go test ./...

# All outbound HTTP must go through internal/egress (also run by go test ./...).
lint:
	go test ./internal/egress/ -run TestNoDirectHTTPOutsideEgress
