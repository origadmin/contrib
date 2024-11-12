module github.com/origadmin/toolkits/contrib/middleware/logger

go 1.23.1

toolchain go1.23.2

replace (
	github.com/origadmin/toolkits => ../../../
	github.com/origadmin/toolkits/codec => ../../../codec
	github.com/origadmin/toolkits/runtime => ../../../runtime
)

require (
	github.com/go-kratos/kratos/v2 v2.8.2
	github.com/origadmin/slog-kratos v1.0.3
	github.com/origadmin/toolkits v0.0.0-00010101000000-000000000000
	github.com/origadmin/toolkits/runtime v0.0.0-00010101000000-000000000000
)

require (
	buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go v1.35.1-20240920164238-5a7b106cbb87.1 // indirect
	cel.dev/expr v0.18.0 // indirect
	dario.cat/mergo v1.0.1 // indirect
	github.com/antlr4-go/antlr/v4 v4.13.1 // indirect
	github.com/bufbuild/protovalidate-go v0.7.2 // indirect
	github.com/go-playground/assert/v2 v2.2.0 // indirect
	github.com/go-playground/form/v4 v4.2.1 // indirect
	github.com/goexts/generic v0.1.0 // indirect
	github.com/golang-cz/devslog v0.0.11 // indirect
	github.com/google/cel-go v0.22.0 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/lmittmann/tint v1.0.5 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/stoewer/go-strcase v1.3.0 // indirect
	golang.org/x/exp v0.0.0-20241108190413-2d47ceb2692f // indirect
	golang.org/x/sys v0.27.0 // indirect
	golang.org/x/text v0.20.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20241104194629-dd2ea8efbc28 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20241104194629-dd2ea8efbc28 // indirect
	google.golang.org/grpc v1.68.0 // indirect
	google.golang.org/protobuf v1.35.1 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.2.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
