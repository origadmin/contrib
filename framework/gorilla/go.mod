module github.com/origadmin/toolkits/contrib/framework/gorilla

go 1.23.0

replace (
	github.com/origadmin/toolkits => ../../../
	github.com/origadmin/toolkits/runtime => ../../../runtime
)

require (
	github.com/gorilla/handlers v1.5.2
	github.com/origadmin/toolkits/runtime v0.0.0-00010101000000-000000000000
)

require (
	buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go v1.35.1-20240920164238-5a7b106cbb87.1 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	google.golang.org/protobuf v1.35.1 // indirect
)
