# Get all dependencies and generate gRPC API
get-deps:
	go get -u google.golang.org/grpc
	go get -u google.golang.org/protobuf/cmd/protoc-gen-go
	go get -u google.golang.org/grpc/cmd/protoc-gen-go-grpc
	go get -u github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-grpc-gateway
	go get -u github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2

generate-api:
	mkdir -p api/sync-auth/v1
	protoc --proto_path=api/proto --proto_path=api/proto \
	--go_out=api/sync-auth/v1 --go_opt=paths=source_relative \
	--go-grpc_out=api/sync-auth/v1 --go-grpc_opt=paths=source_relative \
	--grpc-gateway_out=api/sync-auth/v1 --grpc-gateway_opt=paths=source_relative \
	api/proto/auth.proto

# Build and run the application
build:
	make get-deps
	make generate-api

# Migrations
migrate-up:
	go run cmd/migrations/main.go --migrate=up

migrate-down:
	go run cmd/migrations/main.go --migrate=down

run:
	go run cmd/server/main.go
