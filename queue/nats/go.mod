module github.com/origadmin/toolkits/queue/nats

go 1.23.1

toolchain go1.23.2

replace github.com/origadmin/toolkits => ../../

require (
	github.com/goexts/generic v0.1.1
	github.com/nats-io/nats.go v1.37.0
	github.com/origadmin/toolkits v0.0.0-00010101000000-000000000000
)

require (
	github.com/klauspost/compress v1.17.11 // indirect
	github.com/nats-io/nkeys v0.4.7 // indirect
	github.com/nats-io/nuid v1.0.1 // indirect
	golang.org/x/crypto v0.29.0 // indirect
	golang.org/x/sys v0.27.0 // indirect
)
