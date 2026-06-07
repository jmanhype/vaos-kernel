GO ?= go
PROTO_DIR := proto

.PHONY: build proto test clean mcp

build:
	$(GO) build ./...

proto:
	protoc --proto_path=. \
		--go_out=. --go_opt=module=vaos-kernel \
		--go-grpc_out=. --go-grpc_opt=module=vaos-kernel \
		$(PROTO_DIR)/*.proto

test:
	$(GO) test ./...

clean:
	$(GO) clean ./...

mcp:
	$(GO) build -o bin/vaos-mcp ./cmd/mcp/
