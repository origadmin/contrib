package main

import (
	"context"
	"log"
	"time"

	"github.com/go-kratos/kratos/v2/transport/grpc"

	"github.com/origadmin/contrib/security/middleware"
	"github.com/origadmin/contrib/security/principal"

	// Import the generated client from your backend service
	helloworld "github.com/origadmin/contrib/examples/security-demo/backend/api/helloworld/v1"
)

func main() {
	// For demonstration purposes, we'll create an arbitrary principal.
	// In a real application, this would come from an authenticated session.
	mockPrincipal := principal.New("testuser", "testdomain", principal.WithRoles([]string{"user", "admin"}))

	// Create a middleware factory. We use the default Kratos propagation.
	mwFactory := middleware.NewFactory()

	// Create the client-side middleware.
	clientMiddleware := mwFactory.NewClient()

	// Establish a gRPC connection to the backend service.
	// In a real scenario, this would be the address of your backend service.
	conn, err := grpc.DialInsecure(
		context.Background(),
		grpc.WithEndpoint("127.0.0.1:9000"), // Replace with your backend gRPC address
		grpc.WithMiddleware(clientMiddleware),
	)
	if err != nil {
		log.Fatalf("Failed to dial backend service: %v", err)
	}
	defer conn.Close()

	// Create a context with the principal for the outgoing request.
	ctx := principal.NewContext(context.Background(), mockPrincipal)

	// Simulate calling a backend service method
	log.Printf("Client: Calling backend service...")
	client := helloworld.NewGreeterClient(conn)
	reply, err := client.SayHello(ctx, &helloworld.HelloRequest{Name: "World"})
	if err != nil {
		log.Printf("Client: Failed to call SayHello: %v", err)
		return
	}
	log.Printf("Client: SayHello Reply: %s", reply.GetMessage())

	time.Sleep(time.Second) // Simulate network delay
}
