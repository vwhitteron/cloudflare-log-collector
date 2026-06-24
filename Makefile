# ==================================================================================== #
# HELPERS
# ==================================================================================== #

## help: print this help message
.PHONY: help
help:
	@echo 'Usage:'
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' |  sed -e 's/^/ /'


# ==================================================================================== #
# QUALITY CONTROL
# ==================================================================================== #

## audit: run quality control checks
.PHONY: audit
audit: test
	go mod tidy -diff
	go mod verify
	test -z "$(shell gofmt -l .)" 
	go vet ./...
#   waiting for fix: https://github.com/dominikh/go-tools/issues/1653
# 	go run honnef.co/go/tools/cmd/staticcheck@latest -checks=all,-ST1000,-U1000 ./...
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

## test: run all tests
.PHONY: test
test:
	@go run gotest.tools/gotestsum@latest \
		--format testname  \
		--format-hide-empty-pkg \
		-- -race -buildvcs ./...
	
## test/watch: run all tests re-run when any files change
.PHONY: test/watch
test/watch:
	@go run gotest.tools/gotestsum@latest \
		--format pkgname-and-test-fails \
		--format-icons hivis \
		--format-hide-empty-pkg \
		--watch \
	 	-- -v -race -buildvcs ./...

## test/cover: run all tests and display coverage
.PHONY: test/cover
test/cover:
	go test -v -race -buildvcs -coverprofile=out/coverage.out ./...
	go tool cover -html=out/coverage.out

## upgradeable: list direct dependencies that have upgrades available
.PHONY: upgradeable
upgradeable:
	@go run github.com/oligot/go-mod-upgrade@latest


# ==================================================================================== #
# DEVELOPMENT
# ==================================================================================== #

## lint: run linter against project
.PHONY: lint
lint:
	@golangci-lint run --max-issues-per-linter 0 --max-same-issues 0

## lint/fix: run linter against the project and fix issues where possible
.PHONY: lint/fix
lint/fix:
	@golangci-lint run --fix

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

## build: build the cflog binary for Linux AMD64
.PHONY: build
build:
	GOOS=linux GOARCH=amd64 go build -ldflags="-X main.version=$(VERSION)" -o ./out/cflog ./cflog.go


# ==================================================================================== #
# CONTAINER
# ==================================================================================== #

IMAGE ?= cflog
TAG   ?= latest

## docker/build: build the cflog container image (config baked in)
.PHONY: docker/build
docker/build:
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE):$(TAG) .

## docker/run: run the cflog container image
.PHONY: docker/run
docker/run:
	docker run --rm $(IMAGE):$(TAG)