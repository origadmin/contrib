package main

import (
	"context"
	"fmt"
	"log"
	stdhttp "net/http" // Keep for http.ResponseWriter, http.Request
	"time"

	"github.com/go-kratos/kratos/v2"
	"github.com/go-kratos/kratos/v2/middleware/recovery"
	"github.com/go-kratos/kratos/v2/transport/grpc"
	"github.com/go-kratos/kratos/v2/transport/http" // Import Kratos http for http.Handler
	"github.com/golang-jwt/jwt/v5"

	// Hypothetical backend client. In a real scenario, this would be your generated proto client.
	backendpb "github.com/origadmin/contrib/examples/security-demo/backend/api/helloworld/v1"

	jwtv1 "github.com/origadmin/contrib/api/gen/go/security/authn/jwt/v1"
	authnv1 "github.com/origadmin/contrib/api/gen/go/security/authn/v1"
	jwtAuthn "github.com/origadmin/contrib/security/authn/jwt"
	"github.com/origadmin/contrib/security/middleware"
	"github.com/origadmin/contrib/security/principal"
)

const (
	jwtSecret      = "super-secret-jwt-key"
	jwtIssuer      = "security-gateway"
	backendAddress = "localhost:9000" // Address for the backend service
)

// generateTestJWTToken generates a JWT token for testing.
func generateTestJWTToken(userID string, roles []string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":   userID,
		"roles": roles,
		"iss":   jwtIssuer,
		"exp":   time.Now().Add(time.Hour).Unix(),
	})
	return token.SignedString([]byte(jwtSecret))
}

// resourceHandler implements Kratos http.Handler interface and calls the backend.
type resourceHandler struct {
	backend backendpb.GreeterClient
}

func (h *resourceHandler) SayHello(ctx context.Context, request *backendpb.HelloRequest) (*backendpb.HelloReply, error) {
	return h.backend.SayHello(ctx, request)
}

// ServeHTTP handles the HTTP request, authenticates, and then calls the backend service.
func (h *resourceHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context() // Kratos ensures this context contains middleware-added values
	p, ok := principal.FromContext(ctx)
	if !ok {
		w.WriteHeader(stdhttp.StatusUnauthorized)
		fmt.Fprintf(w, "Unauthorized: Principal not found")
		return
	}

	log.Printf("Gateway: Authenticated principal '%s'. Propagating to backend.", p.GetID())

	// Call the backend service, passing the context to propagate the principal
	reply, err := h.backend.SayHello(ctx, &backendpb.HelloRequest{Name: p.GetID()})
	if err != nil {
		log.Printf("ERROR: Failed to call backend: %v", err)
		w.WriteHeader(stdhttp.StatusInternalServerError)
		fmt.Fprintf(w, "Error calling backend service: %v", err)
		return
	}

	log.Printf("Gateway: Received reply from backend: '%s'", reply.Message)

	w.WriteHeader(stdhttp.StatusOK)
	fmt.Fprintf(w, "Backend Reply: \"%s\" (via Gateway)", reply.Message)
}

func main() {
	// 1. Create the Authenticator
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

	// 2. Create a middleware factory.
	mwFactory := middleware.NewFactory()

	// 3. Create the Gateway middleware for authenticating incoming requests.
	gatewayMiddleware := mwFactory.NewGateway(authenticator, nil)

	// 4. Create the Client middleware for propagating the principal to backend services.
	clientMiddleware := mwFactory.NewClient()

	// --- Backend Client ---
	// Create a gRPC client connection to the backend service.
	// The `clientMiddleware` is crucial here for propagating the identity.
	conn, err := grpc.DialInsecure(
		context.Background(),
		grpc.WithEndpoint(backendAddress),
		grpc.WithMiddleware(
			recovery.Recovery(),
			clientMiddleware,
		),
	)
	if err != nil {
		log.Fatalf("Failed to connect to backend service at %s: %v", backendAddress, err)
	}
	defer conn.Close()

	// Create the specific client for the backend service.
	backendClient := backendpb.NewGreeterClient(conn)
	log.Printf("Successfully connected to backend service at %s", backendAddress)

	// --- HTTP Server ---
	httpSrv := http.NewServer(
		http.Address(":8001"),
		http.Middleware(
			recovery.Recovery(),
			gatewayMiddleware, // Apply gateway middleware to HTTP server
		),
	)
	h := &resourceHandler{backend: backendClient}
	httpSrv.HandlePrefix("/api/v1/resource", h)
	// Register the resource handler, now with the backend client.
	backendpb.RegisterGreeterHTTPServer(httpSrv, h)

	httpSrv.WalkHandle(func(method, path string, handler stdhttp.HandlerFunc) {
		log.Printf("Registered handler for %s %s", method, path)
	})

	// --- gRPC Server (for gateway's own gRPC interface, if any) ---
	// This example doesn't expose its own gRPC endpoints, but the setup is here for completeness.
	grpcSrv := grpc.NewServer(
		grpc.Address(":9001"),
		grpc.Middleware(
			recovery.Recovery(),
			gatewayMiddleware, // Secure gateway's own gRPC endpoints if they existed
		),
	)

	// Create Kratos app
	app := kratos.New(
		kratos.Name("security-gateway"),
		kratos.Version("v1.0"),
		kratos.Server(httpSrv, grpcSrv),
	)

	// Generate a test token for easy testing
	testToken, err := generateTestJWTToken("testuser", []string{"user", "admin"})
	if err != nil {
		log.Fatalf("Failed to generate test token: %v", err)
	}
	log.Printf("Generated test JWT for 'testuser': Bearer %s", testToken)
	log.Println("Try: curl -H \"Authorization: Bearer <token_above>\" http://localhost:8001/api/v1/resource")
	log.Println("Try (unauthenticated): curl http://localhost:8001/api/v1/resource")
	log.Printf("NOTE: This gateway now requires a running backend service at %s", backendAddress)

	// Start the application
	if err := app.Run(); err != nil {
		log.Fatalf("Failed to run gateway: %v", err)
	}
}
