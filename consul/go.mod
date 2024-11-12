module github.com/origadmin/toolkits/contrib/consul

go 1.23.1

toolchain go1.23.2

replace (
	github.com/armon/go-metrics v0.5.4 => github.com/origadmin/go-metrics v0.5.4
	github.com/origadmin/toolkits => ../../
	github.com/origadmin/toolkits/runtime => ../../runtime
)

require (
	github.com/go-kratos/kratos/contrib/config/consul/v2 v2.0.0-20241105072421-f8b97f675b32
	github.com/go-kratos/kratos/contrib/registry/consul/v2 v2.0.0-20241105072421-f8b97f675b32
	github.com/hashicorp/consul/api v1.30.0
	github.com/origadmin/toolkits v0.0.0-00010101000000-000000000000
	github.com/origadmin/toolkits/runtime v0.0.0-00010101000000-000000000000
)

require (
	buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go v1.35.1-20240920164238-5a7b106cbb87.1 // indirect
	cel.dev/expr v0.18.0 // indirect
	dario.cat/mergo v1.0.1 // indirect
	github.com/antlr4-go/antlr/v4 v4.13.1 // indirect
	github.com/armon/go-metrics v0.5.4 // indirect
	github.com/bufbuild/protovalidate-go v0.7.2 // indirect
	github.com/fatih/color v1.18.0 // indirect
	github.com/go-kratos/kratos/v2 v2.8.2 // indirect
	github.com/google/cel-go v0.22.0 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/go-hclog v1.6.3 // indirect
	github.com/hashicorp/go-immutable-radix v1.3.1 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/go-rootcerts v1.0.2 // indirect
	github.com/hashicorp/golang-lru v1.0.2 // indirect
	github.com/hashicorp/serf v0.10.1 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/stoewer/go-strcase v1.3.0 // indirect
	golang.org/x/exp v0.0.0-20241108190413-2d47ceb2692f // indirect
	golang.org/x/sys v0.27.0 // indirect
	golang.org/x/text v0.20.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20241104194629-dd2ea8efbc28 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20241104194629-dd2ea8efbc28 // indirect
	google.golang.org/protobuf v1.35.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
