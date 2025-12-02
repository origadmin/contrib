package main

import (
	"fmt"
	"log"
	stdhttp "net/http" // Keep for http.ResponseWriter, http.Request
	"time"

	"github.com/go-kratos/kratos/v2"
	"github.com/go-kratos/kratos/v2/middleware/recovery"
	"github.com/go-kratos/kratos/v2/transport/grpc"
	"github.com/go-kratos/kratos/v2/transport/http" // Import Kratos http for http.Handler
	"github.com/golang-jwt/jwt/v5"

	jwtv1 "github.com/origadmin/contrib/api/gen/go/security/authn/jwt/v1"
	authnv1 "github.com/origadmin/contrib/api/gen/go/security/authn/v1"
	jwtAuthn "github.com/origadmin/contrib/security/authn/jwt"
	"github.com/origadmin/contrib/security/middleware"
	"github.com/origadmin/contrib/security/principal"
)

const (
	jwtSecret = "super-secret-jwt-key"
	jwtIssuer = "security-gateway"
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

// resourceHandler implements Kratos http.Handler interface
type resourceHandler struct{}

// ServeHTTP handles the HTTP request.
// It now uses Kratos's http.ResponseWriter and http.Request types.
func (h *resourceHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context() // Kratos ensures this context contains middleware-added values
	log.Printf("Handler: Request context address: %p", ctx) // Log context address in handler
	p, ok := principal.FromContext(ctx)
	if !ok {
		log.Printf("Handler: Principal not found in context %p", ctx) // Log if principal is not found
		w.WriteHeader(stdhttp.StatusUnauthorized)
		fmt.Fprintf(w, "Unauthorized: Principal not found")
		return
	}

	log.Printf("Gateway: Authenticated principal '%s'. Propagating to backend.", p.GetID())

	w.WriteHeader(stdhttp.StatusOK)
	fmt.Fprintf(w, "Hello, %s! (Authenticated by Gateway)", p.GetID())
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

	// 2. Create a middleware factory. We use the default Kratos propagation.
	mwFactory := middleware.NewFactory()

	// 3. Create the Gateway middleware. It only needs the authenticator.
	gatewayMiddleware := mwFactory.NewGateway(authenticator, nil)

	// --- HTTP Server ---
	httpSrv := http.NewServer(
		http.Address(":8001"),
		http.Middleware(
			recovery.Recovery(),
			gatewayMiddleware, // Apply gateway middleware to HTTP server
		),
	)

	// Register the Kratos http.Handler using HandlePrefix
	httpSrv.HandlePrefix("/api/v1/resource", &resourceHandler{})

	// --- gRPC Server (optional, demonstrating Kratos app with multiple transports) ---
	grpcSrv := grpc.NewServer(
		grpc.Address(":9001"), // This is typically where backend services listen
		grpc.Middleware(
			recovery.Recovery(),
			gatewayMiddleware, // Apply gateway middleware to gRPC server
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

	// Start the application
	if err := app.Run(); err != nil {
		log.Fatalf("Failed to run gateway: %v", err)
	}
}
