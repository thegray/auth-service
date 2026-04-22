.PHONY: run test build

run:
	go run ./cmd/server

build:
	go build ./...

test:
	go test ./...
