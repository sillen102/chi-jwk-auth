.PHONY: test lint

test:
	@go test ./... -v

lint:
	@golangci-lint run ./...

update-deps:
	@go get -u ./...
	@go mod tidy
