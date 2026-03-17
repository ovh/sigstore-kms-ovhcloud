.PHONY: build clean install lint re test tool

BINARY	=	sigstore-kms-ovhcloudkms
BIN_DIR	=	bin

CMD_PATH	=	./cmd/sigstore-kms-ovhcloudkms

GO	=	go
GOLANGCI_LINT = $(TOOLS_BIN)/golangci-lint

SRC	=	./...

TOOLS_BIN = $(CURDIR)/bin

PREFIX	?=	/usr/local

build:
	@echo " > Building $(BINARY)..."
	@$(GO) build -o $(BIN_DIR)/$(BINARY) $(CMD_PATH) \
		&& echo "Build succeeded: $(BIN_DIR)/$(BINARY)\n" \
		|| echo "Build failed\n"

clean:
	@echo " > Cleaning..."
	@rm -f $(BINARY)

install: build
	@echo " > Installing $(BINARY) to $(PREFIX)/bin..."
	@mkdir -p $(PREFIX)/bin
	@cp $(BIN_DIR)/$(BINARY) $(PREFIX)/bin \
		&& echo "Done. $(BINARY) is installed in $(PREFIX)/bin" \
		|| echo "Try: sudo make install\n or change the installation path: make install PREFIX=<PREFIX>"

lint: tool
	@echo " > Linting code..."
	@$(GOLANGCI_LINT) run

re: clean build

test:
	@echo " > Running tests..."
	$(GO) test -v $(SRC)

tool:
	@echo " > Installing tools..."
	GOBIN=$(TOOLS_BIN) go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.11.3
