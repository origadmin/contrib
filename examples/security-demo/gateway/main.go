package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/go-kratos/kratos/v2"
	"github.com/go-kratos/kratos/v2/middleware/recovery"
	"github.com/go-kratos/kratos/v2/transport/grpc"
	"github.com/go-kratos/kratos/v2/transport/http" // Import Kratos http for http.Handler
	"github.com/golang-jwt/jwt/v5"

	// Backend client from the security-demo example.
	backendpb "github.com/origadmin/contrib/examples/security-demo/backend/api/helloworld/v1"

	jwtv1 "github.com/origadmin/contrib/api/gen/go/security/authn/jwt/v1"
	authnv1 "github.com/origadmin/contrib/api/gen/go/security/authn/v1"
	jwtAuthn "github.com/origadmin/contrib/security/authn/jwt"
	"github.com/origadmin/contrib/security/middleware"
	"github.com/origadmin/contrib/security/principal"
)

const (
	// Secret and issuer for authenticating end-user JWTs.
	jwtSecret      = "super-secret-jwt-key"
	jwtIssuer      = "security-gateway"
	backendAddress = "localhost:9000" // Address for the backend service
)

// generateTestJWTToken generates a JWT token for end-user testing.
func generateTestJWTToken(userID string, roles []string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":   userID,
		"roles": roles,
		"iss":   jwtIssuer,
		"exp":   time.Now().Add(time.Hour).Unix(),
	})
	return token.SignedString([]byte(jwtSecret))
}

// resourceHandler implements the gRPC service interface.
// It acts as a bridge, receiving gRPC calls and forwarding them to the backend.
type resourceHandler struct {
	backendpb.UnimplementedGreeterServer // Embed for forward compatibility
	backend                              backendpb.GreeterClient
}

// SayHello is the gRPC-level handler. It authenticates the principal from the context
// and calls the backend, propagating the principal.
func (h *resourceHandler) SayHello(ctx context.Context, request *backendpb.HelloRequest) (*backendpb.HelloReply, error) {
	p, ok := principal.FromContext(ctx)
	if !ok {
		// This should ideally not be reached if middleware is configured correctly.
		return nil, fmt.Errorf("unauthorized: principal not found in context")
	}
	log.Printf("[gRPC Handler] Authenticated principal '%s'. Propagating to backend.", p.GetID())

	// Call the backend service, passing the context to propagate the principal.
	// We use the principal's ID as the name in the request.
	return h.backend.SayHello(ctx, &backendpb.HelloRequest{Name: p.GetID()})
}

func main() {
	// 1. Create the Authenticator for incoming user requests.
	authenticator, err := jwtAuthn.NewAuthenticator(&authnv1.Authenticator{
		Type: "jwt",
		Jwt: &jwtv1.Config{
			SigningMethod: "HS256",
			SigningKey:    jwtSecret,
			Issuer:        jwtIssuer,
		},
	})
	if err != nil {
		log.Fatalf("Failed to create authenticator: %v", err)
	}

	// 2. Create the middleware factory.
	mwFactory := middleware.NewFactory()

	// 3. Create the Gateway Middleware for the server-side.
	// This middleware authenticates incoming requests using the authenticator.
	gatewayMiddleware := mwFactory.NewGateway(authenticator, nil)

	// 4. Create the Client Middleware for the client-side.
	// With a nil authenticator, this middleware propagates the principal found in the context.
	clientMiddleware := mwFactory.NewClient()

	// --- Backend Client Setup ---
	conn, err := grpc.DialInsecure(
		context.Background(),
		grpc.WithEndpoint(backendAddress),
		grpc.WithMiddleware(
			recovery.Recovery(),
			clientMiddleware, // This is crucial for propagating the user's identity.
		),
	)
	if err != nil {
		log.Fatalf("Failed to connect to backend service at %s: %v", backendAddress, err)
	}
	defer conn.Close()

	backendClient := backendpb.NewGreeterClient(conn)
	log.Printf("Successfully connected to backend service at %s", backendAddress)

	// --- Server Setup ---
	h := &resourceHandler{backend: backendClient}

	httpSrv := http.NewServer(
		http.Address(":8001"),
		http.Middleware(
			recovery.Recovery(),
			gatewayMiddleware, // Apply server-side authentication.
		),
	)
	// Register the gRPC-Gateway endpoint. This exposes the gRPC service over HTTP.
	backendpb.RegisterGreeterHTTPServer(httpSrv, h)

	grpcSrv := grpc.NewServer(
		grpc.Address(":9001"),
		grpc.Middleware(
			recovery.Recovery(),
			gatewayMiddleware, // Also secure the gRPC server.
		),
	)
	// Register the gRPC server.
	backendpb.RegisterGreeterServer(grpcSrv, h)

	// --- App Start ---
	app := kratos.New(
		kratos.Name("security-gateway"),
		kratos.Version("v1.0"),
		kratos.Server(httpSrv, grpcSrv),
	)

	testToken, err := generateTestJWTToken("testuser", []string{"user", "admin"})
	if err != nil {
		log.Fatalf("Failed to generate test token: %v", err)
	}
	log.Printf("Generated test JWT for 'testuser': Bearer %s", testToken)
	log.Println("---")
	log.Println("This gateway authenticates a user, then propagates the user's identity to the backend.")
	log.Println("Try via gRPC-Gateway: curl -H \"Authorization: Bearer <token>\" http://localhost:8001/api/v1/sayhello")
	log.Printf("NOTE: This requires a running backend service at %s that can validate the propagated principal.", backendAddress)

	if err := app.Run(); err != nil {
		log.Fatalf("Failed to run gateway: %v", err)
	}
}
