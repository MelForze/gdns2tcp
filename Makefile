.PHONY: all build clients servers cover clean test

BUILD_DIR  := clients
SERVER_DIR := servers
CLIENT_PKG := ./cmd/gdns2tcp-client
SERVER_PKG := ./cmd/gdns2tcp
GO_FILES   := $(shell find cmd internal -name '*.go')

all: build

build:
	go build ./cmd/gdns2tcp ./cmd/gdns2tcp-client

clients: \
	$(BUILD_DIR)/gdns2tcp-client-linux-amd64 \
	$(BUILD_DIR)/gdns2tcp-client-linux-arm64 \
	$(BUILD_DIR)/gdns2tcp-client-darwin-amd64 \
	$(BUILD_DIR)/gdns2tcp-client-darwin-arm64 \
	$(BUILD_DIR)/gdns2tcp-client.ps1

servers: \
	$(SERVER_DIR)/gdns2tcp-server-linux-amd64 \
	$(SERVER_DIR)/gdns2tcp-server-linux-arm64 \
	$(SERVER_DIR)/gdns2tcp-server-darwin-amd64 \
	$(SERVER_DIR)/gdns2tcp-server-darwin-arm64

$(SERVER_DIR)/gdns2tcp-server-linux-amd64: $(GO_FILES)
	GOOS=linux GOARCH=amd64 go build -o $@ $(SERVER_PKG)

$(SERVER_DIR)/gdns2tcp-server-linux-arm64: $(GO_FILES)
	GOOS=linux GOARCH=arm64 go build -o $@ $(SERVER_PKG)

$(SERVER_DIR)/gdns2tcp-server-darwin-amd64: $(GO_FILES)
	GOOS=darwin GOARCH=amd64 go build -o $@ $(SERVER_PKG)

$(SERVER_DIR)/gdns2tcp-server-darwin-arm64: $(GO_FILES)
	GOOS=darwin GOARCH=arm64 go build -o $@ $(SERVER_PKG)

$(BUILD_DIR)/gdns2tcp-client-linux-amd64: $(GO_FILES)
	GOOS=linux GOARCH=amd64 go build -o $@ $(CLIENT_PKG)

$(BUILD_DIR)/gdns2tcp-client-linux-arm64: $(GO_FILES)
	GOOS=linux GOARCH=arm64 go build -o $@ $(CLIENT_PKG)

$(BUILD_DIR)/gdns2tcp-client-darwin-amd64: $(GO_FILES)
	GOOS=darwin GOARCH=amd64 go build -o $@ $(CLIENT_PKG)

$(BUILD_DIR)/gdns2tcp-client-darwin-arm64: $(GO_FILES)
	GOOS=darwin GOARCH=arm64 go build -o $@ $(CLIENT_PKG)

$(BUILD_DIR)/gdns2tcp-client.ps1: scripts/gdns2tcp-client.ps1
	cp $< $@

test:
	go test -race ./...

cover:
	go test -coverprofile=cover.out -covermode=atomic ./...
	go tool cover -func=cover.out

clean:
	rm -f \
		gdns2tcp gdns2tcp-client \
		$(BUILD_DIR)/gdns2tcp-client-linux-amd64 \
		$(BUILD_DIR)/gdns2tcp-client-linux-arm64 \
		$(BUILD_DIR)/gdns2tcp-client-darwin-amd64 \
		$(BUILD_DIR)/gdns2tcp-client-darwin-arm64 \
		$(SERVER_DIR)/gdns2tcp-server-linux-amd64 \
		$(SERVER_DIR)/gdns2tcp-server-linux-arm64 \
		$(SERVER_DIR)/gdns2tcp-server-darwin-amd64 \
		$(SERVER_DIR)/gdns2tcp-server-darwin-arm64
