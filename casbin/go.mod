module github.com/origadmin/toolkits/contrib/casbin

go 1.23.0

toolchain go1.23.2

replace (
	github.com/casbin/ent-adapter v1.0.1 => github.com/origadmin/ent-adapter v1.0.1
	github.com/origadmin/toolkits => ../../
	github.com/origadmin/toolkits/runtime => ../../runtime
)

require (
	github.com/casbin/casbin/v2 v2.101.0
	github.com/casbin/ent-adapter v1.0.1
)

require (
	ariga.io/atlas v0.25.0 // indirect
	entgo.io/ent v0.14.0 // indirect
	github.com/agext/levenshtein v1.2.3 // indirect
	github.com/apparentlymart/go-textseg/v15 v15.0.0 // indirect
	github.com/bmatcuk/doublestar/v4 v4.6.1 // indirect
	github.com/casbin/govaluate v1.2.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/go-openapi/inflect v0.21.0 // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/hashicorp/hcl/v2 v2.21.0 // indirect
	github.com/mitchellh/go-wordwrap v1.0.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/zclconf/go-cty v1.15.0 // indirect
	golang.org/x/mod v0.20.0 // indirect
	golang.org/x/sync v0.9.0 // indirect
	golang.org/x/text v0.20.0 // indirect
	golang.org/x/tools v0.24.0 // indirect
)
