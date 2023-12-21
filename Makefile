.PHONY: update-deps lint test

update-deps:
	@go get -u ./...
	@go mod tidy

lint:
	@golangci-lint run ./...

test:
	@go test ./... -v
