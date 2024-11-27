module github.com/origadmin/toolkits/contrib/cache

go 1.23.1

toolchain go1.23.2

replace (
	github.com/origadmin/toolkits => ../../
	github.com/origadmin/toolkits/runtime => ../../runtime
)

require (
	github.com/coocood/freecache v1.2.4
	github.com/goexts/generic v0.1.1
	github.com/origadmin/toolkits/errors v0.0.5
	github.com/origadmin/toolkits/runtime v0.0.8
)

require (
	buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go v1.35.2-20240920164238-5a7b106cbb87.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	golang.org/x/exp v0.0.0-20241108190413-2d47ceb2692f // indirect
	google.golang.org/protobuf v1.35.2 // indirect
)
