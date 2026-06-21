.PHONY: all build clients servers cover clean test .FORCE

BUILD_DIR  := clients
SERVER_DIR := servers
CLIENT_PKG := ./cmd/gdns2tcp-client
SERVER_PKG := ./cmd/gdns2tcp
PROXY_PKG  := ./cmd/gdns2tcp-client-proxy


# Per-architecture binaries depend on .FORCE so the recipe always fires;
# `go build` itself caches incrementally and is fast on no-op rebuilds. This
# avoids the macOS/APFS quirk where mtime comparison occasionally misses
# recently-edited source files.
.FORCE:

all: build

build:
	go build ./cmd/gdns2tcp ./cmd/gdns2tcp-client ./cmd/gdns2tcp-client-proxy

clients: \
	$(BUILD_DIR)/gdns2tcp-client-linux-amd64 \
	$(BUILD_DIR)/gdns2tcp-client-linux-arm64 \
	$(BUILD_DIR)/gdns2tcp-client-darwin-amd64 \
	$(BUILD_DIR)/gdns2tcp-client-darwin-arm64 \
	$(BUILD_DIR)/gdns2tcp-client.ps1 \
	$(BUILD_DIR)/gdns2tcp-client-proxy-linux-amd64 \
	$(BUILD_DIR)/gdns2tcp-client-proxy-linux-arm64 \
	$(BUILD_DIR)/gdns2tcp-client-proxy-darwin-amd64 \
	$(BUILD_DIR)/gdns2tcp-client-proxy-darwin-arm64 \
	$(BUILD_DIR)/gdns2tcp-client-proxy-windows-amd64.exe \
	$(BUILD_DIR)/gdns2tcp-client-proxy-windows-arm64.exe

servers: \
	$(SERVER_DIR)/gdns2tcp-server-linux-amd64 \
	$(SERVER_DIR)/gdns2tcp-server-linux-arm64 \
	$(SERVER_DIR)/gdns2tcp-server-darwin-amd64 \
	$(SERVER_DIR)/gdns2tcp-server-darwin-arm64

$(SERVER_DIR)/gdns2tcp-server-linux-amd64: .FORCE
	GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o $@ $(SERVER_PKG)

$(SERVER_DIR)/gdns2tcp-server-linux-arm64: .FORCE
	GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o $@ $(SERVER_PKG)

$(SERVER_DIR)/gdns2tcp-server-darwin-amd64: .FORCE
	GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o $@ $(SERVER_PKG)

$(SERVER_DIR)/gdns2tcp-server-darwin-arm64: .FORCE
	GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o $@ $(SERVER_PKG)

$(BUILD_DIR)/gdns2tcp-client-linux-amd64: .FORCE
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $@ $(CLIENT_PKG)

$(BUILD_DIR)/gdns2tcp-client-linux-arm64: .FORCE
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $@ $(CLIENT_PKG)

$(BUILD_DIR)/gdns2tcp-client-darwin-amd64: .FORCE
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $@ $(CLIENT_PKG)

$(BUILD_DIR)/gdns2tcp-client-darwin-arm64: .FORCE
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $@ $(CLIENT_PKG)

$(BUILD_DIR)/gdns2tcp-client.ps1: scripts/gdns2tcp-client.ps1
	cp $< $@

$(BUILD_DIR)/gdns2tcp-client-proxy-linux-amd64: .FORCE
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $@ $(PROXY_PKG)

$(BUILD_DIR)/gdns2tcp-client-proxy-linux-arm64: .FORCE
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $@ $(PROXY_PKG)

$(BUILD_DIR)/gdns2tcp-client-proxy-darwin-amd64: .FORCE
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $@ $(PROXY_PKG)

$(BUILD_DIR)/gdns2tcp-client-proxy-darwin-arm64: .FORCE
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $@ $(PROXY_PKG)

$(BUILD_DIR)/gdns2tcp-client-proxy-windows-amd64.exe: .FORCE
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $@ $(PROXY_PKG)

$(BUILD_DIR)/gdns2tcp-client-proxy-windows-arm64.exe: .FORCE
	GOOS=windows GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $@ $(PROXY_PKG)

test:
	go test -race ./...

cover:
	go test -coverprofile=cover.out -covermode=atomic ./...
	go tool cover -func=cover.out

clean:
	rm -f \
		gdns2tcp gdns2tcp-client gdns2tcp-client-proxy \
		$(BUILD_DIR)/gdns2tcp-client-linux-amd64 \
		$(BUILD_DIR)/gdns2tcp-client-linux-arm64 \
		$(BUILD_DIR)/gdns2tcp-client-darwin-amd64 \
		$(BUILD_DIR)/gdns2tcp-client-darwin-arm64 \
		$(BUILD_DIR)/gdns2tcp-client-proxy-linux-amd64 \
		$(BUILD_DIR)/gdns2tcp-client-proxy-linux-arm64 \
		$(BUILD_DIR)/gdns2tcp-client-proxy-darwin-amd64 \
		$(BUILD_DIR)/gdns2tcp-client-proxy-darwin-arm64 \
		$(BUILD_DIR)/gdns2tcp-client-proxy-windows-amd64.exe \
		$(BUILD_DIR)/gdns2tcp-client-proxy-windows-arm64.exe \
		$(SERVER_DIR)/gdns2tcp-server-linux-amd64 \
		$(SERVER_DIR)/gdns2tcp-server-linux-arm64 \
		$(SERVER_DIR)/gdns2tcp-server-darwin-amd64 \
		$(SERVER_DIR)/gdns2tcp-server-darwin-arm64
