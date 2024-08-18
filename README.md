# SYNC-AUTH

Auth microservice for social network "SYNC". This project is currently under development.

## Installation

Ensure you have the `protoc` binary in your path. Run next commands if you don't have grpc support in Go yet:

```bash
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-grpc-gateway
```

Generate the code by command in the Makefile:

```bash
make build
```

## Configuration setup

### .env example

Make sure you have a .env file in the root directory with the following content:

```env
ENV=local
LOG_LEVEL=info
PORT=44044

# TOKEN MANAGEMENT SETTINGS
TOKENS_ACCESS_TTL=15m
TOKENS_REFRESH_TTL=720h
REDIS_ADDR=127.0.0.1:6379
TOKENS_SECRET=my_token_secret

# POSTGRES SETTINGS
POSTGRES_USER=postgres
POSTGRES_PASSWORD=admin
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DBNAME=sync
POSTGRES_SSLMODE=disable

# EMAIL VERIFICATION
EMAIL_CODE_TTL=240s
APP_EMAIL=someone@gmail.com
APP_PASSWORD=dkjfjkwdfjwj

# OAUTH GITHUB
GITHUB_CLIENT_ID=my_app_id
GITHUB_CLIENT_SECRET=my_app_secret
```

### Features

This service supports Authorization through Github and email verification. So you need a github app and work google email address to use it.

### Migrations

**Set Up the Database:**
Make sure you have a PostgreSQL database created that matches the settings in your .env file.

**Run Migrations:**
Use the following command to run migrations:

```bash
make migrate-up
```

## Running the app

Run the next command to run service:

```bash
make run
```
