package middleware

import (
	"log"

	"github.com/go-kratos/kratos/v2"
	kratosMiddleware "github.com/go-kratos/kratos/v2/middleware"
	"github.com/go-kratos/kratos/v2/transport/grpc"
	"github.com/go-kratos/kratos/v2/transport/http"

	jwtv1 "github.com/origadmin/contrib/api/gen/go/security/authn/jwt/v1"
	authnv1 "github.com/origadmin/contrib/api/gen/go/security/authn/v1"
	authzv1 "github.com/origadmin/contrib/api/gen/go/security/authz/v1"
	jwtAuthn "github.com/origadmin/contrib/security/authn/jwt"
	"github.com/origadmin/contrib/security/authz"
	"github.com/origadmin/contrib/security/authz/casbin"
)

// ExampleFactoryNewGateway demonstrates how to set up a gateway server.
// A gateway authenticates requests and then relies on the transport to propagate the principal.
func ExampleFactoryNewGateway() {
	// 1. Create the authenticator
	authenticator, err := jwtAuthn.NewAuthenticator(&authnv1.Authenticator{
		Type: "jwt",
		Jwt: &jwtv1.Config{
			SigningMethod: "HS256",
			SigningKey:    "your-secret-key",
		},
	})
	if err != nil {
		log.Fatalf("Failed to create authenticator: %v", err)
	}

	// 2. Create a middleware factory with a chosen propagation type.
	// This factory can be shared across services to ensure consistency.
	// 2. Create a middleware factory. By default, it uses Kratos propagation.
	// To use a different type, pass it as an argument, e.g., middleware.NewFactory(principal.PropagationTypeGRPC).
	mwFactory := NewFactory()

	// 3. Create the gateway middleware.
	// It only needs the authenticator. We pass nil for the skip checker for simplicity.
	gatewayMiddleware := mwFactory.NewGateway(authenticator, nil)

	// 4. Apply the middleware to the server.
	httpSrv := http.NewServer(
		http.Middleware(gatewayMiddleware),
	)
	app := kratos.New(kratos.Name("gateway"), kratos.Server(httpSrv))
	log.Printf("Gateway server setup complete with middleware: %v", app)
	// Output:
}

// ExampleFactoryNewBackend demonstrates how to set up a backend server.
// A backend server expects a principal in the context and performs authorization.
func ExampleFactoryNewBackend() {
	// 1. Create the authorizer
	authorizer, err := casbin.NewAuthorizer(&authzv1.Authorizer{Type: authz.Casbin})
	if err != nil {
		log.Fatalf("Failed to create authorizer: %v", err)
	}

	// 2. Create a middleware factory with a propagation type *consistent with the gateway*.
	// 2. Create a middleware factory. By default, it uses Kratos propagation.
	// To use a different type, pass it as an argument, e.g., middleware.NewFactory(principal.PropagationTypeGRPC).
	mwFactory := NewFactory()

	// 3. Create the backend middleware.
	// It needs the authorizer to check permissions.
	backendMiddleware := mwFactory.NewBackend(authorizer, nil)

	// 4. Apply the middleware to the server.
	grpcSrv := grpc.NewServer(
		grpc.Middleware(backendMiddleware),
	)
	app := kratos.New(kratos.Name("backend-service"), kratos.Server(grpcSrv))
	log.Printf("Backend server setup complete with middleware: %v", app)
	// Output:
}

// ExampleFactoryNewStandalone demonstrates how to set up a service that handles both
// authentication and authorization.
func ExampleFactoryNewStandalone() {
	// 1. Create the authenticator
	authenticator, err := jwtAuthn.NewAuthenticator(&authnv1.Authenticator{
		Type: "jwt",
		Jwt: &jwtv1.Config{
			SigningMethod: "HS256",
			SigningKey:    "your-secret-key",
		},
	})
	if err != nil {
		log.Fatalf("Failed to create authenticator: %v", err)
	}

	// 2. Create the authorizer
	authorizer, err := casbin.NewAuthorizer(&authzv1.Authorizer{Type: authz.Casbin})
	if err != nil {
		log.Fatalf("Failed to create authorizer: %v", err)
	}

	// 3. Create a middleware factory. The propagation type is less critical here unless
	// this service also acts as a client to other backend services.
	// 2. Create a middleware factory. By default, it uses Kratos propagation.
	// To use a different type, pass it as an argument, e.g., middleware.NewFactory(principal.PropagationTypeGRPC).
	mwFactory := NewFactory()

	// 4. Create the standalone middleware, providing both components.
	standaloneMiddleware := mwFactory.NewStandalone(authenticator, authorizer, nil, nil)

	// 5. Apply the middleware to the server.
	httpSrv := http.NewServer(
		http.Middleware(standaloneMiddleware),
	)
	app := kratos.New(kratos.Name("standalone-service"), kratos.Server(httpSrv))
	log.Printf("Standalone server setup complete with middleware: %v", app)
	// Output:
}

// ExampleFactoryNewClient demonstrates how to set up a client to propagate credentials.
func ExampleFactoryNewClient() {
	// 1. Create a middleware factory with a propagation type *consistent with the servers*.
	// 2. Create a middleware factory. By default, it uses Kratos propagation.
	// To use a different type, pass it as an argument, e.g., middleware.NewFactory(principal.PropagationTypeGRPC).
	mwFactory := NewFactory()

	// 2. Create the client middleware. It has no dependencies as it only reads from the context.
	clientMiddleware := mwFactory.NewClient()

	// 3. Apply the middleware to a client connection (example with gRPC).
	// conn, err := grpc.Dial(
	// 	context.Background(),
	// 	grpc.WithEndpoint("dns:///backend-service:9000"),
	// 	grpc.WithMiddleware(clientMiddleware),
	// )
	// if err != nil {
	// 	log.Fatalf("Failed to dial backend: %v", err);
	// }
	// log.Printf("Client connection setup complete with middleware: %v", conn)

	// Dummy middleware for compilation
	var _ kratosMiddleware.Middleware = clientMiddleware
	log.Printf("Client middleware created: %v", clientMiddleware)
	// Output:
}
