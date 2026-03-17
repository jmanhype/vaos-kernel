GO ?= go
PROTO_DIR := proto

.PHONY: build proto test clean

build:
	$(GO) build ./...

proto:
	protoc --proto_path=$(PROTO_DIR) --go_out=. --go-grpc_out=. $(PROTO_DIR)/*.proto

test:
	$(GO) test ./...

clean:
	$(GO) clean ./...
