# Contributing

## Requirements

- Go 1.27 (the `toolchain` line in `go.mod` pins the patch release)
- golangci-lint v2.14.0

## Before you open a pull request

```
go mod tidy -diff
golangci-lint run ./...
go test -race -shuffle=on -count=1 ./...
GOFIPS140=certified GODEBUG=fips140=only go test -count=1 ./...
go run ./internal/cmd/mitigations
```

## Rules

- Follow the governing RFC for any protocol behavior. If no RFC covers it, open an issue before writing code.
- Use the standard library first. A new dependency needs a reason in the pull request.
- Every security property has a test that fails when the property is removed. A new mitigation gets a row in `THREAT_MODEL.md` naming its test.
- Never weaken a test, lint rule or CI gate to make a change pass.
- Commits and pull request titles use [Conventional Commits](https://www.conventionalcommits.org/).
- Commits are signed.
