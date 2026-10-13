module github.com/parallelworks/relay/bench

go 1.27.0

toolchain go1.27.2

require (
	github.com/coder/websocket v1.8.15
	github.com/parallelworks/relay v0.0.0
	go.uber.org/goleak v1.3.0
	golang.org/x/perf v0.0.0-20261009192801-be2c69fb417e
)

require (
	github.com/aclements/go-moremath v0.0.0-20210112150236-f10218a38794 // indirect
	github.com/go-jose/go-jose/v4 v4.1.5 // indirect
)

replace github.com/parallelworks/relay => ../
