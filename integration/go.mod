module github.com/parallelworks/relay/integration

go 1.27.0

toolchain go1.27.3

require (
	github.com/parallelworks/relay v0.0.0
	github.com/pkg/sftp v1.13.11
	go.uber.org/goleak v1.3.0
	golang.org/x/crypto v0.58.0
)

require (
	github.com/go-jose/go-jose/v4 v4.1.5 // indirect
	github.com/kr/fs v0.1.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
)

replace github.com/parallelworks/relay => ../
