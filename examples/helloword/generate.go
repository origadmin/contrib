/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package helloword

////go:generate protoc --proto_path=. --proto_path=../third_party --go_out=paths=source_relative:. --go-gins_out=paths=source_relative:. ./helloworld/helloworld.proto
////go:generate protoc --proto_path=. --proto_path=../third_party --go_out=paths=source_relative:. --go-grpc_out=paths=source_relative:. ./helloworld/helloworld.proto
////go:generate protoc --proto_path=. --proto_path=../third_party --go_out=paths=source_relative:. --go-http_out=paths=source_relative:. ./helloworld/helloworld.proto
////go:generate protoc --proto_path=. --proto_path=../third_party --go_out=paths=source_relative:. --go-errors_out=paths=source_relative:. ./helloworld/helloworld.proto
////go:generate protoc --proto_path=. --proto_path=../third_party --go_out=paths=source_relative:. ./helloworld/helloworld.proto
////go:generate protoc --proto_path=. --proto_path=../third_party --openapiv2_out . --openapiv2_opt logtostderr=true ./helloworld/helloworld.proto
//go get -u github.com/go-kratos/kratos/cmd/kratos/v2
//go get -u google.golang.org/protobuf/cmd/protoc-gen-go
//go get -u google.golang.org/grpc/cmd/protoc-gen-go-grpc
//go get -u github.com/go-kratos/kratos/cmd/protoc-gen-go-http/v2
//go get -u github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2
//go get -u github.com/google/wire/cmd/wire

//go:generate buf dep update
//go:generate buf build
//go:generate buf generate
