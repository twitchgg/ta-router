BINARY := ta-registry
BINARY_VERSION := v1.0.0
BUILD_DIR := ./build
RPC_DIR := ./pkg/proto
OUT_DIR := ./pkg/pb

.PHONY: clean-build clean-all

all: clean-all compile-all

init:
	go mod tidy
	mkdir -p $(BUILD_DIR)

compile-linux: init
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags '-s -w' \
		-o $(BUILD_DIR)/$(BINARY)-$(BINARY_VERSION)-linux-amd64 
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags '-s -w' \
		-o $(BUILD_DIR)/$(BINARY)-$(BINARY_VERSION)-linux-arm64
	GOOS=linux GOARCH=arm CGO_ENABLED=0 go build -ldflags '-s -w' \
		-o $(BUILD_DIR)/$(BINARY)-$(BINARY_VERSION)-linux-arm

compile-all: compile-proto compile-linux

compile-proto: init clean-proto
	for f in $$(ls $(RPC_DIR)/*.proto) ; do \
	 	protoc --proto_path=. --go_out=$(OUT_DIR) \
			--go-grpc_out=require_unimplemented_servers=false:$(OUT_DIR) $$f ;  \
	done

clean-proto:
	rm -f $(OUT_DIR)/*.pb.go

clean-build:
	rm -rf $(BUILD_DIR)

clean-all: clean-build
