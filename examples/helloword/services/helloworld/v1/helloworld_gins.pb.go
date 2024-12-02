// Code generated by protoc-gen-go-gins. DO NOT EDIT.
// versions:
// - protoc-gen-go-gins 0.0.93
// - protoc             (unknown)
// source: helloworld/v1/helloworld.proto

package helloworld

import (
	context "context"
	gin "github.com/gin-gonic/gin"
	binding "github.com/go-kratos/kratos/v2/transport/http/binding"
	gins "github.com/origadmin/runtime/transport/gins"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the kratos package it is being compiled against.
var _ = new(context.Context)
var _ = new(gin.H)
var _ = binding.EncodeURL

const _ = gins.SupportPackageIsVersion1

const GreeterService_SayHello_OperationName = "/helloworld.v1.GreeterService/SayHello"

type GreeterServiceGINSServer interface {
	// SayHello Sends a greeting
	SayHello(context.Context, *SayHelloRequest) (*SayHelloResponse, error)
}

func RegisterGreeterServiceGINSServer(router gin.IRouter, srv GreeterServiceGINSServer) {
	router.POST("/say_hello", _GreeterService_SayHello0_GIN_Handler(srv))
	router.GET("/helloworld/:name", _GreeterService_SayHello1_GIN_Handler(srv))
}

func _GreeterService_SayHello0_GIN_Handler(srv GreeterServiceGINSServer) func(ctx *gin.Context) {
	return func(ctx *gin.Context) {
		var in SayHelloRequest
		if err := gins.BindBody(ctx, &in); err != nil {
			gins.RetError(ctx, err)
			return
		}
		if err := gins.BindQuery(ctx, &in); err != nil {
			gins.RetError(ctx, err)
			return
		}
		gins.SetOperation(ctx, GreeterService_SayHello_OperationName)
		newCtx := gins.NewContext(ctx)
		reply, err := srv.SayHello(newCtx, &in)
		if err != nil {
			gins.RetError(ctx, err)
			return
		}
		gins.RetJSON(ctx, 200, reply)
		return
	}
}

func _GreeterService_SayHello1_GIN_Handler(srv GreeterServiceGINSServer) func(ctx *gin.Context) {
	return func(ctx *gin.Context) {
		var in SayHelloRequest
		if err := gins.BindQuery(ctx, &in); err != nil {
			gins.RetError(ctx, err)
			return
		}
		if err := gins.BindURI(ctx, &in); err != nil {
			gins.RetError(ctx, err)
			return
		}
		gins.SetOperation(ctx, GreeterService_SayHello_OperationName)
		newCtx := gins.NewContext(ctx)
		reply, err := srv.SayHello(newCtx, &in)
		if err != nil {
			gins.RetError(ctx, err)
			return
		}
		gins.RetJSON(ctx, 200, reply)
		return
	}
}

type GreeterServiceGINSClient interface {
	SayHello(ctx context.Context, req *SayHelloRequest, opts ...gins.CallOption) (rsp *SayHelloResponse, err error)
}

type GreeterServiceGINSClientImpl struct {
	cc *gins.Client
}

func NewGreeterServiceGINSClient(client *gins.Client) GreeterServiceGINSClient {
	return &GreeterServiceGINSClientImpl{client}
}

func (c *GreeterServiceGINSClientImpl) SayHello(ctx context.Context, in *SayHelloRequest, opts ...gins.CallOption) (*SayHelloResponse, error) {
	var out SayHelloResponse
	pattern := "/helloworld/{name}"
	path := binding.EncodeURL(pattern, in, true)
	opts = append(opts, gins.Operation(GreeterService_SayHello_OperationName))
	opts = append(opts, gins.PathTemplate(pattern))
	err := c.cc.Invoke(ctx, "GET", path, nil, &out, opts...)
	if err != nil {
		return nil, err
	}
	return &out, nil
}
