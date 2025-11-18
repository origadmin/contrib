package main_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-kratos/kratos/v2/errors"
	"github.com/go-kratos/kratos/v2/middleware"
	kratosgrpc "github.com/go-kratos/kratos/v2/transport/grpc"
	kratoshttp "github.com/go-kratos/kratos/v2/transport/http"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/emptypb"

	securityv1 "github.com/origadmin/runtime/api/gen/go/config/security/v1"
	"github.com/origadmin/runtime/interfaces/security/declarative"
	impl "github.com/origadmin/runtime/security/declarative"
)

const (
	validToken   = "valid-token"
	invalidToken = "invalid-token"
	authHeader   = "Authorization"
)

// --- 1. Mocks and Test Components ---

// MockPrincipal implements declarative.Principal
type MockPrincipal struct {
	ID     string
	Roles  []string
	Claims map[string]*anypb.Any
}

func (mp *MockPrincipal) GetID() string {
	return mp.ID
}

func (mp *MockPrincipal) GetRoles() []string {
	return mp.Roles
}

func (mp *MockPrincipal) GetClaims() map[string]any {
	panic("TODO")
}

// mockAuthenticator implements the Authenticator interface for testing.
type mockAuthenticator struct {
	validToken string
}

func (m *mockAuthenticator) Authenticate(ctx context.Context, cred declarative.Credential) (declarative.Principal, error) {
	var token securityv1.BearerCredential
	if err := cred.ParsedPayload(&token); err != nil {
		return nil, errors.Unauthorized("UNAUTHORIZED", "invalid token format")
	}
	if token.Token != m.validToken {
		return nil, errors.Unauthorized("UNAUTHORIZED", "invalid token")
	}
	return &MockPrincipal{ID: "test-user", Roles: []string{"user"}}, nil
}

func (m *mockAuthenticator) Supports(cred declarative.Credential) bool {
	return strings.ToLower(cred.Type()) == "jwt"
}

// --- 2. Middleware/Interceptor Implementation ---

// kratosSecurityMiddleware is the core logic for our security middleware/interceptor for Kratos.
func kratosSecurityMiddleware(authenticators []declarative.Authenticator, extractor declarative.CredentialExtractor) middleware.Middleware {
	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req interface{}) (interface{}, error) {
			provider, err := impl.FromServerContext(ctx)
			if err != nil {
				return nil, err
			}

			if provider == nil {
				return nil, errors.InternalServer("UNKNOWN_REQUEST_TYPE", "request type not supported by security middleware")
			}

			// 1. Extract Credential
			cred, err := extractor.Extract(ctx, provider) // Pass ctx here
			if err != nil {
				return nil, errors.Unauthorized("CREDENTIAL_MISSING", err.Error())
			}

			// 2. Find a suitable Authenticator
			var authenticator declarative.Authenticator
			for _, auth := range authenticators {
				if auth.Supports(cred) {
					authenticator = auth
					break
				}
			}
			if authenticator == nil {
				return nil, errors.Unauthorized("AUTHENTICATOR_NOT_FOUND", "no authenticator found for credential type: "+cred.Type())
			}

			// 3. Authenticate
			principal, err := authenticator.Authenticate(ctx, cred)
			if err != nil {
				return nil, err // Return the error from the authenticator
			}

			// 4. Inject Principal into context
			newCtx := declarative.PrincipalWithContext(ctx, principal)

			// For Kratos, simply pass the new context down the chain.
			// Kratos's http.Server will handle propagating this context to the http.Request's context.
			return handler(newCtx, req)
		}
	}
} // standardSecurityMiddleware is the core logic for our security middleware/interceptor for standard net/http.
func standardSecurityMiddleware(authenticators []declarative.Authenticator, extractor declarative.CredentialExtractor) middleware.Middleware {
	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req interface{}) (interface{}, error) {
			var provider declarative.ValueProvider

			// Adapt request to ValueProvider
			if r, ok := req.(*http.Request); ok {
				provider = impl.FromHTTPRequest(r)
			} else {
				// This middleware is specifically for standard net/http.
				// If it's not an http.Request, it's an unexpected scenario for this middleware.
				return nil, errors.InternalServer("UNEXPECTED_REQUEST_TYPE", "standardSecurityMiddleware expects *http.Request")
			}

			if provider == nil {
				return nil, errors.InternalServer("UNKNOWN_REQUEST_TYPE", "request type not supported by security middleware")
			}

			// 1. Extract Credential
			cred, err := extractor.Extract(ctx, provider) // Pass ctx here
			if err != nil {
				return nil, errors.Unauthorized("CREDENTIAL_MISSING", err.Error())
			}

			// 2. Find a suitable Authenticator
			var authenticator declarative.Authenticator
			for _, auth := range authenticators {
				if auth.Supports(cred) {
					authenticator = auth
					break
				}
			}
			if authenticator == nil {
				return nil, errors.Unauthorized("AUTHENTICATOR_NOT_FOUND", "no authenticator found for credential type: "+cred.Type())
			}

			// 3. Authenticate
			principal, err := authenticator.Authenticate(ctx, cred)
			if err != nil {
				return nil, err // Return the error from the authenticator
			}

			// 4. Inject Principal into context
			newCtx := declarative.PrincipalWithContext(ctx, principal)

			// For standard net/http, we must create a new request with the new context
			if r, ok := req.(*http.Request); ok {
				*r = *r.WithContext(newCtx)
				return handler(newCtx, r)
			}
			// This should not be reached if the initial check for *http.Request passed.
			return nil, errors.InternalServer("UNEXPECTED_STATE", "standardSecurityMiddleware failed to update http.Request")
		}
	}
}

// TestServiceHTTP defines a simple HTTP service for Kratos.
type TestServiceHTTP interface {
	TestCall(context.Context, *emptypb.Empty) (*emptypb.Empty, error)
}

// testServiceHTTPImpl implements TestServiceHTTP.
type testServiceHTTPImpl struct {
	t *testing.T
}

func (s *testServiceHTTPImpl) TestCall(ctx context.Context, req *emptypb.Empty) (*emptypb.Empty, error) {
	p, ok := declarative.PrincipalFromContext(ctx)
	assert.True(s.t, ok, "Principal should be in Kratos HTTP context (native handler)")
	if ok {
		assert.Equal(s.t, "test-user", p.GetID())
	}
	return &emptypb.Empty{}, nil
}

func RegisterTestServiceHTTPServer(s *kratoshttp.Server, srv TestServiceHTTP) {
	r := s.Route("/")
	r.GET("/test", testServiceCallHTTPHandler(srv))
}

func testServiceCallHTTPHandler(srv TestServiceHTTP) func(ctx kratoshttp.Context) error {
	return func(ctx kratoshttp.Context) error {
		var in emptypb.Empty
		// No binding needed for empty request
		// if err := ctx.BindQuery(&in); err != nil {
		// 	return err
		// }
		// http.SetOperation(ctx, OperationTestServiceTestCall) // No operation constant needed for manual test
		h := ctx.Middleware(func(ctx context.Context, req interface{}) (interface{}, error) {
			return srv.TestCall(ctx, req.(*emptypb.Empty))
		})
		out, err := h(ctx, &in)
		if err != nil {
			return err
		}
		reply := out.(*emptypb.Empty)
		return ctx.Result(200, reply)
	}
}

// authFilterFunc is a standard net/http middleware (FilterFunc) that performs authentication
// and injects the Principal into the http.Request's context.
func authFilterFunc(authenticators []declarative.Authenticator, extractor declarative.CredentialExtractor) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			provider := impl.FromHTTPRequest(r)

			cred, err := extractor.Extract(r.Context(), provider) // Pass r.Context() here
			if err != nil {
				http.Error(w, errors.Unauthorized("CREDENTIAL_MISSING", err.Error()).Error(), http.StatusUnauthorized)
				return
			}

			var authenticator declarative.Authenticator
			for _, auth := range authenticators {
				if auth.Supports(cred) {
					authenticator = auth
					break
				}
			}
			if authenticator == nil {
				http.Error(w, errors.Unauthorized("AUTHENTICATOR_NOT_FOUND", "no authenticator found for credential type: "+cred.Type()).Error(), http.StatusUnauthorized)
				return
			}

			principal, err := authenticator.Authenticate(r.Context(), cred)
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}

			newCtx := declarative.PrincipalWithContext(r.Context(), principal)
			next.ServeHTTP(w, r.WithContext(newCtx)) // Inject new context into the request
		})
	}
}

// --- 3. Test Scenarios ---

func TestMiddlewareIntegration(t *testing.T) {
	// --- Setup common components ---
	auth := &mockAuthenticator{validToken: validToken}
	extractor := impl.NewHeaderCredentialExtractor()
	kratosSecurityChain := kratosSecurityMiddleware([]declarative.Authenticator{auth}, extractor)
	standardSecurityChain := standardSecurityMiddleware([]declarative.Authenticator{auth}, extractor)

	// --- Scenario 1: Standard net/http Server ---
	t.Run("Standard net/http", func(t *testing.T) {
		// The final handler that checks for the principal
		finalHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, ok := declarative.PrincipalFromContext(r.Context())
			assert.True(t, ok, "Principal should be in context")
			if ok {
				assert.Equal(t, "test-user", p.GetID())
			}
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, "OK")
		})

		// Adapt the Kratos middleware to a standard http.Handler
		middlewareAdapter := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				kratosHandler := func(ctx context.Context, req interface{}) (interface{}, error) {
					next.ServeHTTP(w, req.(*http.Request))
					return "ok", nil
				}

				_, err := standardSecurityChain(kratosHandler)(r.Context(), r)

				if err != nil {
					if se := errors.FromError(err); se != nil {
						http.Error(w, se.Message, int(se.Code))
					} else {
						http.Error(w, err.Error(), http.StatusInternalServerError)
					}
				}
			})
		}

		server := httptest.NewServer(middlewareAdapter(finalHandler))
		defer server.Close()

		// Test with valid token
		req, _ := http.NewRequest("GET", server.URL, nil)
		req.Header.Set(authHeader, "Bearer "+validToken)
		resp, err := server.Client().Do(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()

		// Test with invalid token
		req, _ = http.NewRequest("GET", server.URL, nil)
		req.Header.Set(authHeader, "Bearer "+invalidToken)
		resp, err = server.Client().Do(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		resp.Body.Close()
	})

	// --- Scenario 2: Kratos HTTP Server ---
	t.Run("Kratos HTTP", func(t *testing.T) {
		srv := kratoshttp.NewServer(
			kratoshttp.Address("127.0.0.1:0"),
			kratoshttp.Middleware(kratosSecurityChain),
		)

		// Create an instance of the Kratos-native service implementation
		testService := &testServiceHTTPImpl{t: t}

		// Register the service using the manually created registration function
		RegisterTestServiceHTTPServer(srv, testService)

		go func() {
			if err := srv.Start(context.Background()); err != nil && !errors.Is(err, http.ErrServerClosed) {
				panic(err)
			}
		}()
		defer srv.Stop(context.Background())
		time.Sleep(100 * time.Millisecond)

		endpoint, err := srv.Endpoint()
		assert.NoError(t, err)
		assert.NotNil(t, endpoint)

		client := &http.Client{}

		// Test with valid token
		req, _ := http.NewRequest("GET", endpoint.String()+"/test", nil)
		req.Header.Set(authHeader, "Bearer "+validToken)
		resp, err := client.Do(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()

		// Test with invalid token
		req, _ = http.NewRequest("GET", endpoint.String()+"/test", nil)
		req.Header.Set(authHeader, "Bearer "+invalidToken)
		resp, err = client.Do(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		resp.Body.Close()
	})

	// --- Scenario 4: Kratos HTTP Server with http.HandlerFunc Context Propagation ---
	t.Run("Kratos HTTP - HandlerFunc Context Propagation", func(t *testing.T) {
		// Handler that checks for principal
		httpHandler := func(w http.ResponseWriter, r *http.Request) {
			p, ok := declarative.PrincipalFromContext(r.Context())
			assert.True(t, ok, "Principal should be in Kratos HTTP context (HandlerFunc) via FilterFunc")
			if ok {
				assert.Equal(t, "test-user", p.GetID())
			}
			w.WriteHeader(http.StatusOK)
		}

		srv := kratoshttp.NewServer(
			kratoshttp.Address("127.0.0.1:0"),
			kratoshttp.Filter(authFilterFunc([]declarative.Authenticator{auth}, extractor)), // Use FilterFunc
		)
		srv.Handle("/test-handlerfunc", http.HandlerFunc(httpHandler))

		go func() {
			if err := srv.Start(context.Background()); err != nil && !errors.Is(err, http.ErrServerClosed) {
				panic(err)
			}
		}()
		defer srv.Stop(context.Background())
		time.Sleep(100 * time.Millisecond)

		endpoint, err := srv.Endpoint()
		assert.NoError(t, err)
		assert.NotNil(t, endpoint)

		client := &http.Client{}

		// Test with valid token
		req, _ := http.NewRequest("GET", endpoint.String()+"/test-handlerfunc", nil)
		req.Header.Set(authHeader, "Bearer "+validToken)
		resp, err := client.Do(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()

		// Test with invalid token
		req, _ = http.NewRequest("GET", endpoint.String()+"/test-handlerfunc", nil)
		req.Header.Set(authHeader, "Bearer "+invalidToken)
		resp, err = client.Do(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		resp.Body.Close()
	})

	// --- Scenario 3: Kratos gRPC Server ---
	t.Run("Kratos gRPC", func(t *testing.T) {
		// Simple gRPC handler
		handler := func(ctx context.Context, req interface{}) (interface{}, error) {
			p, ok := declarative.PrincipalFromContext(ctx)
			assert.True(t, ok, "Principal should be in Kratos gRPC context")
			if ok {
				assert.Equal(t, "test-user", p.GetID())
			}
			return &emptypb.Empty{}, nil // Return a proto.Message
		}

		lis, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to listen: %v", err)
		}
		addr := lis.Addr().String()
		lis.Close()

		srv := kratosgrpc.NewServer(
			kratosgrpc.Address(addr),
			kratosgrpc.Middleware(kratosSecurityChain), // Use kratosSecurityChain
		)

		gsd := &grpc.ServiceDesc{
			ServiceName: "test.Service",
			HandlerType: (*interface{})(nil),
			Methods: []grpc.MethodDesc{
				{
					MethodName: "TestCall",
					Handler: func(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
						if interceptor == nil {
							return handler(ctx, nil)
						}
						info := &grpc.UnaryServerInfo{
							Server:     srv,
							FullMethod: "/test.Service/TestCall",
						}
						return interceptor(ctx, nil, info, handler)
					},
				},
			},
		}
		srv.RegisterService(gsd, struct{}{})

		go func() {
			if err := srv.Start(context.Background()); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
				panic(err)
			}
		}()
		defer srv.Stop(context.Background())
		time.Sleep(100 * time.Millisecond)

		conn, err := grpc.Dial(addr, grpc.WithInsecure())
		assert.NoError(t, err)
		defer conn.Close()

		// Test with valid token
		ctxValid := metadata.NewOutgoingContext(context.Background(), metadata.Pairs(authHeader, "Bearer "+validToken))
		var reply emptypb.Empty
		err = conn.Invoke(ctxValid, "/test.Service/TestCall", &emptypb.Empty{}, &reply)
		assert.NoError(t, err)

		// Test with invalid token
		ctxInvalid := metadata.NewOutgoingContext(context.Background(), metadata.Pairs(authHeader, "Bearer "+invalidToken))
		err = conn.Invoke(ctxInvalid, "/test.Service/TestCall", &emptypb.Empty{}, &reply)
		assert.Error(t, err)
		st, ok := status.FromError(err)
		assert.True(t, ok)
		assert.Equal(t, codes.Unauthenticated, st.Code())
	})
}
