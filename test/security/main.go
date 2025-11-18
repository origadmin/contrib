package main

import (
	"os"
	"time"

	"github.com/go-kratos/kratos/v2"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-kratos/kratos/v2/middleware/recovery"
	"github.com/go-kratos/kratos/v2/transport/grpc"
	"github.com/go-kratos/kratos/v2/transport/http"

	v1 "github.com/origadmin/runtime/examples/protos/security/api/v1"
	exampleSecurity "github.com/origadmin/runtime/examples/security/internal/security"
	"github.com/origadmin/runtime/examples/security/internal/service"
	"github.com/origadmin/runtime/interfaces/options"
	"github.com/origadmin/runtime/middleware/declarative"
)

// go:generate go run github.com/google/wire/cmd/wire

func main() {
	// Register the custom component factory for our PolicyProvider before starting the runtime.
	// This tells the runtime how to create the 'policy.provider' component.
	// 1. Manually create the Policy Provider.
	// In a real app, this would be created by the runtime's bootstrap process.
	policyProvider := exampleSecurity.NewPolicyProvider()

	// 2. Create Greeter Service
	greeterSrv := service.NewGreeterService()

	opts := declarative.FromOptions([]options.Option{
		declarative.WithPolicyProvider(policyProvider),
		declarative.WithDefaultPolicy("authn-only"),
	})
	// 3. Manually create the Security Middleware, injecting the policy provider.
	// This demonstrates the direct creation of the middleware.
	securityMiddleware := declarative.SecurityMiddleware(opts)

	// 4. Create HTTP Server and apply the middleware
	httpSrv := http.NewServer(
		http.Address(":8000"),
		http.Timeout(time.Second),
		http.Middleware(
			recovery.Recovery(),
			securityMiddleware,
		),
	)
	v1.RegisterGreeterHTTPServer(httpSrv, greeterSrv)

	// 5. Create gRPC Server and apply the middleware
	grpcSrv := grpc.NewServer(
		grpc.Address(":9000"),
		grpc.Middleware(
			recovery.Recovery(),
			securityMiddleware,
		),
	)
	v1.RegisterGreeterServer(grpcSrv, greeterSrv)

	// 6. Create and run the Kratos App
	app := newApp(log.DefaultLogger, grpcSrv, httpSrv)

	if err := app.Run(); err != nil {
		log.Errorf("Error running app: %v", err)
		os.Exit(1)
	}
}

// newApp creates a Kratos application instance.
// It takes a logger and server instances to construct the Kratos App.
func newApp(logger log.Logger, gs *grpc.Server, hs *http.Server) *kratos.App {
	return kratos.New(
		kratos.Name("security-example"),
		kratos.Version("v1.0.0"),
		kratos.Metadata(map[string]string{}),
		kratos.Logger(logger),
		kratos.Server(
			gs,
			hs,
		),
	)
}
