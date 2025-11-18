package service

import (
	"context"
	"fmt"

	"github.com/go-kratos/kratos/v2/errors" // Import the kratos errors package

	v1 "github.com/origadmin/runtime/examples/protos/security/api/v1"
	"github.com/origadmin/runtime/interfaces/security/declarative"
)

// GreeterService is a simple greeter service.
type GreeterService struct {
	v1.UnimplementedGreeterServer
}

// NewGreeterService creates a new GreeterService.
func NewGreeterService() *GreeterService {
	return &GreeterService{}
}

// SayHelloPublic handles public access requests.
func (s *GreeterService) SayHelloPublic(ctx context.Context, req *v1.HelloRequest) (*v1.HelloReply, error) {
	p, ok := declarative.PrincipalFromContext(ctx)
	if !ok {
		return &v1.HelloReply{Message: fmt.Sprintf("Hello %s (Public, Anonymous)", req.Name)}, nil
	}
	return &v1.HelloReply{Message: fmt.Sprintf("Hello %s (Public, ID: %s)", req.Name, p.GetID())}, nil
}

// SayHelloAuthenticated handles authenticated access requests.
func (s *GreeterService) SayHelloAuthenticated(ctx context.Context, req *v1.HelloRequest) (*v1.HelloReply, error) {
	p, ok := declarative.PrincipalFromContext(ctx)
	if !ok {
		// This should ideally not happen if middleware works correctly
		return nil, errors.Unauthorized("UNAUTHENTICATED", "Principal not found in context") // Use errors.Unauthorized
	}
	return &v1.HelloReply{Message: fmt.Sprintf("Hello %s (Authenticated, ID: %s)", req.Name, p.GetID())}, nil
}

// SayHelloAuthorized handles authorized access requests.
func (s *GreeterService) SayHelloAuthorized(ctx context.Context, req *v1.HelloRequest) (*v1.HelloReply, error) {
	p, ok := declarative.PrincipalFromContext(ctx)
	if !ok {
		// This should ideally not happen if middleware works correctly
		return nil, errors.Unauthorized("UNAUTHENTICATED", "Principal not found in context") // Use errors.Unauthorized
	}
	return &v1.HelloReply{Message: fmt.Sprintf("Hello %s (Authorized, ID: %s, Roles: %v)", req.Name, p.GetID(), p.GetRoles())}, nil
}

// mustEmbedUnimplementedGreeterServer ensures forward compatibility.
func (s *GreeterService) mustEmbedUnimplementedGreeterServer() {}
