BIN_NAME := tuxproxy
SRC_DIR := ./cmd/tuxproxy
INSTALL_DIR ?= $(HOME)/.local/bin

.PHONY: all build install clean test

all: build

build:
	@echo "==> Building $(BIN_NAME)..."
	go build -ldflags="-s -w" -o $(BIN_NAME) $(SRC_DIR)
	@echo "==> Successfully built $(BIN_NAME)"

install: build
	@echo "==> Installing $(BIN_NAME) to $(INSTALL_DIR)..."
	mkdir -p $(INSTALL_DIR)
	install -m 755 $(BIN_NAME) $(INSTALL_DIR)/$(BIN_NAME)
	@echo "==> Installed $(BIN_NAME) in $(INSTALL_DIR)/$(BIN_NAME)"

clean:
	@echo "==> Cleaning build artifacts..."
	rm -f $(BIN_NAME)

test:
	go test -v ./...
