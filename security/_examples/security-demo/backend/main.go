package main

import (
	"context"
	"log"

	"github.com/go-kratos/kratos/v2"
	"github.com/go-kratos/kratos/v2/errors"
	"github.com/go-kratos/kratos/v2/middleware/recovery"
	"github.com/go-kratos/kratos/v2/transport/grpc"

	"github.com/casbin/casbin/v3/model"
	stringadapter "github.com/casbin/casbin/v3/persist/string-adapter"

	authzv1 "github.com/origadmin/contrib/api/gen/go/security/authz/v1"
	securityv1 "github.com/origadmin/contrib/api/gen/go/security/v1"
	"github.com/origadmin/contrib/security/authz"
	"github.com/origadmin/contrib/security/authz/casbin"
	"github.com/origadmin/contrib/security/middleware"
	"github.com/origadmin/contrib/security/principal"

	// Import the generated helloworld service
	helloworld "github.com/origadmin/contrib/security/_examples/security-demo/backend/api/helloworld/v1"
)

// Greeter Service
type greeterService struct {
	helloworld.UnimplementedGreeterServer
}

// SayHello implements helloworld.GreeterServer
func (s *greeterService) SayHello(ctx context.Context, in *helloworld.HelloRequest) (*helloworld.HelloReply, error) {
	p, ok := principal.FromContext(ctx)
	if !ok {
		return nil, errors.New(401, securityv1.SecurityErrorReason_CREDENTIALS_INVALID.String(),
			"principal not found in context")
	}
	log.Printf("Backend: SayHello called by principal: %s, roles: %v", p.GetID(), p.GetRoles())

	// Here you would implement your business logic, possibly using the principal for further checks.
	return &helloworld.HelloReply{Message: "Hello " + in.GetName() + ", from backend. Authenticated as: " + p.GetID()}, nil
}

// initCasbinAuthorizer creates a Casbin authorizer with a predefined model and policy.
func initCasbinAuthorizer() authz.Authorizer {
	casbinModelText := `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
`
	// Allow 'admin' to read/write '/admin'
	// Allow 'editor' to edit '/documents'
	// Allow any authenticated user ('user') to view '/documents'
	// Allow 'user' to call '/helloworld.Greeter/SayHello'
	casbinPolicyText := `
p, admin, /admin, read
p, admin, /admin, write
p, editor, /documents, edit
p, user, /documents, view
p, user, /helloworld.v1.Greeter/SayHello, /helloworld.v1.Greeter/SayHello
g, testuser, user
g, testuser, admin
`
	m, err := model.NewModelFromString(casbinModelText)
	if err != nil {
		log.Fatalf("Failed to load Casbin model: %v", err)
	}
	sa := stringadapter.NewAdapter(casbinPolicyText)

	authorizer, err := casbin.NewAuthorizer(
		&authzv1.Authorizer{Type: authz.Casbin},
		casbin.WithModel(m),
		casbin.WithPolicyAdapter(sa),
	)
	if err != nil {
		log.Fatalf("Failed to create Casbin authorizer: %v", err)
	}
	return authorizer
}

func main() {
	// 1. Initialize the Casbin Authorizer
	authorizer := initCasbinAuthorizer()

	// 2. Create a middleware factory. We expect Kratos propagation from the Gateway/Client.
	mwFactory := middleware.NewFactory()

	// 3. Create the Backend middleware. It needs the authorizer.
	backendMiddleware := mwFactory.NewBackend(authorizer, nil)

	// Create gRPC Server
	grpcSrv := grpc.NewServer(
		grpc.Address(":9000"), // This matches the client's dial address
		grpc.Middleware(
			recovery.Recovery(),
			backendMiddleware,
		),
	)

	// Register the simulated GreeterService
	helloworld.RegisterGreeterServer(grpcSrv, &greeterService{})

	// Create Kratos app
	app := kratos.New(
		kratos.Name("security-backend"),
		kratos.Version("v1.0"),
		kratos.Server(grpcSrv),
	)

	log.Println("Backend service starting on gRPC :9000")
	// Start the application
	if err := app.Run(); err != nil {
		log.Fatalf("Failed to run backend service: %v", err)
	}
}
