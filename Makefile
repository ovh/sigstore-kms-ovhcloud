.PHONY: build clean install lint re test tool

BINARY	=	sigstore-kms-ovhcloudkms
BIN_DIR	=	$(CURDIR)/bin
BUILD_DIR = $(CURDIR)/build

CMD_PATH	=	./cmd/sigstore-kms-ovhcloudkms

GO	=	go
GOLANGCI_LINT = $(BIN_DIR)/golangci-lint
GOTESTSUM = $(BIN_DIR)/gotestsum

SRC	=	./...

PREFIX	?=	/usr/local

build:
	@echo " > Building $(BINARY)..."
	@$(GO) build -o $(BUILD_DIR)/$(BINARY) $(CMD_PATH) \
		&& echo "Build succeeded: $(BUILD_DIR)/$(BINARY)\n" \
		|| echo "Build failed\n"

clean:
	@echo " > Cleaning..."
	@rm -rf $(BUILD_DIR)

install: build
	@echo " > Installing $(BINARY) to $(PREFIX)/bin..."
	@mkdir -p $(PREFIX)/bin
	@cp $(BUILD_DIR)/$(BINARY) $(PREFIX)/bin \
		&& echo "Done. $(BINARY) is installed in $(PREFIX)/bin" \
		|| echo "Try: sudo make install\n or change the installation path: make install PREFIX=<PREFIX>"

lint: tool
	@echo " > Linting code..."
	@$(GOLANGCI_LINT) run

re: clean build

test: tool
	@echo " > Running tests..."
	@mkdir -p $(BUILD_DIR)
	go test -v -json -coverprofile=$(BUILD_DIR)/coverage.out ./... > $(BUILD_DIR)/test-results.json
	$(GOTESTSUM) --junitfile=$(BUILD_DIR)/junit.xml --raw-command -- cat $(BUILD_DIR)/test-results.json
	go tool cover -html=$(BUILD_DIR)/coverage.out -o $(BUILD_DIR)/coverage.html

tool:
	@echo " > Installing tools..."
	GOBIN=$(BIN_DIR) go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.11.3
	GOBIN=$(BIN_DIR) go install gotest.tools/gotestsum@v1.13.0
