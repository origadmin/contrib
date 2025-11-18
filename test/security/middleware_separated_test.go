package main_test

import (
	"context"
	"fmt"
	"io"
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
	separatedValidToken   = "separated-valid-token"
	separatedInvalidToken = "separated-invalid-token"
	separatedAuthHeader   = "Authorization"
	separatedTestResource = "/test"
	separatedTestAction   = "read"
)

// --- 1. Mocks and Test Components for Separated Middleware ---

// MockPrincipal implements declarative.Principal
type SeparatedMockPrincipal struct {
	ID     string
	Roles  []string
	Claims map[string]*anypb.Any
}

func (mp *SeparatedMockPrincipal) GetID() string {
	return mp.ID
}

func (mp *SeparatedMockPrincipal) GetRoles() []string {
	return mp.Roles
}

func (mp *SeparatedMockPrincipal) GetClaims() map[string]any {
	// For this test, we don't need to return actual claims, just satisfy the interface.
	return nil
}

// mockAuthenticator implements the Authenticator interface for testing.
type SeparatedMockAuthenticator struct {
	validToken string
	t          *testing.T // Add testing.T for logging
}

func (m *SeparatedMockAuthenticator) Authenticate(ctx context.Context, cred declarative.Credential) (declarative.Principal, error) {
	if m.t != nil {
		m.t.Logf("[DEBUG] Authenticate called with credential type: %s", cred.Type())
	}
	var token securityv1.BearerCredential
	if err := cred.ParsedPayload(&token); err != nil {
		if m.t != nil {
			m.t.Logf("[ERROR] Failed to parse token: %v", err)
		}
		return nil, errors.Unauthorized("UNAUTHORIZED", "invalid token format or type mismatch")
	}
	if m.t != nil {
		m.t.Logf("[DEBUG] Authenticating token: %s, expected: %s", token.Token, m.validToken)
	}
	if token.Token != m.validToken {
		if m.t != nil {
			m.t.Logf("[ERROR] Token mismatch: got %s, want %s", token.Token, m.validToken)
		}
		return nil, errors.Unauthorized("UNAUTHORIZED", "invalid token")
	}
	principal := &SeparatedMockPrincipal{ID: "separated-test-user", Roles: []string{"user"}}
	if m.t != nil {
		m.t.Logf("[DEBUG] Authentication successful for user: %s", principal.ID)
	}
	return principal, nil
}

func (m *SeparatedMockAuthenticator) Supports(cred declarative.Credential) bool {
	supported := strings.ToLower(cred.Type()) == "jwt"
	if m.t != nil {
		m.t.Logf("[DEBUG] MockAuthenticator.Supports: type=%s, supported=%v", cred.Type(), supported)
	}
	return supported
}

// mockAuthorizer implements the Authorizer interface for testing.
type SeparatedMockAuthorizer struct {
	// For simplicity, this mock always authorizes if a principal is present.
	// In a real scenario, it would check principal roles, resource, action against policies.
}

func (ma *SeparatedMockAuthorizer) Authorize(ctx context.Context, p declarative.Principal, resourceIdentifier string, action string) (bool, error) {
	// For this test, we'll just check if the principal exists.
	// A real authorizer would perform more complex logic.
	if p == nil || p.GetID() == "" {
		return false, errors.Forbidden("FORBIDDEN", "principal not found or invalid")
	}
	// Simulate a successful authorization for any valid principal
	return true, nil
}

// --- 2. Separated Middleware/Interceptor Implementations ---

// kratosAuthnMiddleware is the core logic for our authentication middleware/interceptor for Kratos.
func kratosAuthnMiddleware(authenticator declarative.Authenticator, extractor declarative.CredentialExtractor) middleware.Middleware {
	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req interface{}) (interface{}, error) {
			provider, err := impl.FromServerContext(ctx)
			if err != nil {
				return nil, err
			}

			if provider == nil {
				return nil, errors.InternalServer("UNKNOWN_REQUEST_TYPE", "request type not supported by authentication middleware")
			}

			// 1. Extract Credential
			cred, err := extractor.Extract(ctx, provider) // Pass ctx here
			if err != nil {
				return nil, errors.Unauthorized("CREDENTIAL_MISSING", err.Error())
			}

			// 2. Authenticate
			principal, err := authenticator.Authenticate(ctx, cred)
			if err != nil {
				return nil, err // Return the error from the authenticator
			}

			// 3. Inject Principal into context
			newCtx := declarative.PrincipalWithContext(ctx, principal)

			return handler(newCtx, req)
		}
	}
}

// kratosAuthzMiddleware is the core logic for our authorization middleware/interceptor for Kratos.
func kratosAuthzMiddleware(authorizer declarative.Authorizer, resourceIdentifier string, action string) middleware.Middleware {
	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req interface{}) (interface{}, error) {
			// 1. Get Principal from context (assumes authentication middleware ran before)
			principal, ok := declarative.PrincipalFromContext(ctx)
			if !ok {
				return nil, errors.Unauthorized("UNAUTHENTICATED", "principal not found in context, authentication required")
			}

			// 2. Authorize
			allowed, err := authorizer.Authorize(ctx, principal, resourceIdentifier, action)
			if err != nil {
				return nil, err // Return the error from the authorizer
			}
			if !allowed {
				return nil, errors.Forbidden("PERMISSION_DENIED", "principal not authorized for this resource/action")
			}

			return handler(ctx, req)
		}
	}
}

// standardAuthnMiddleware is the core logic for our authentication middleware/interceptor for standard net/http.
func standardAuthnMiddleware(t *testing.T, authenticator declarative.Authenticator, extractor declarative.CredentialExtractor) middleware.Middleware {
	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req interface{}) (interface{}, error) {
			t.Logf("[DEBUG] standardAuthnMiddleware: Starting authentication")
			var provider declarative.ValueProvider

			if r, ok := req.(*http.Request); ok {
				t.Logf("[DEBUG] standardAuthnMiddleware: Extracting provider from http.Request")
				provider = impl.FromHTTPRequest(r)
				if r.Header != nil {
					t.Logf("[DEBUG] standardAuthnMiddleware: Request headers: %+v", r.Header)
				}
			} else {
				errMsg := "standardAuthnMiddleware expects *http.Request"
				t.Logf("[ERROR] %s", errMsg)
				return nil, errors.InternalServer("UNEXPECTED_REQUEST_TYPE", errMsg)
			}

			if provider == nil {
				errMsg := "request type not supported by authentication middleware"
				t.Logf("[ERROR] %s", errMsg)
				return nil, errors.InternalServer("UNKNOWN_REQUEST_TYPE", errMsg)
			}

			// 1. Extract Credential
			t.Logf("[DEBUG] standardAuthnMiddleware: Extracting credential")
			cred, err := extractor.Extract(ctx, provider)
			if err != nil {
				errMsg := fmt.Sprintf("Failed to extract credential: %v", err)
				t.Logf("[ERROR] %s", errMsg)
				return nil, errors.Unauthorized("CREDENTIAL_MISSING", errMsg)
			}
			t.Logf("[DEBUG] standardAuthnMiddleware: Extracted credential type: %s", cred.Type())

			// 2. Authenticate
			t.Logf("[DEBUG] standardAuthnMiddleware: Authenticating credential")
			principal, err := authenticator.Authenticate(ctx, cred)
			if err != nil {
				t.Logf("[ERROR] Authentication failed: %v", err)
				return nil, err
			}

			t.Logf("[DEBUG] standardAuthnMiddleware: Authentication successful, principal ID: %s", principal.GetID())

			// 3. Inject Principal into context
			newCtx := declarative.PrincipalWithContext(ctx, principal)

			if r, ok := req.(*http.Request); ok {
				*r = *r.WithContext(newCtx)
				t.Logf("[DEBUG] standardAuthnMiddleware: Successfully updated request context with principal")
				return handler(newCtx, r)
			}

			errMsg := "standardAuthnMiddleware failed to update http.Request"
			t.Logf("[ERROR] %s", errMsg)
			return nil, errors.InternalServer("UNEXPECTED_STATE", errMsg)
		}
	}
}

// standardAuthzMiddleware is the core logic for our authorization middleware/interceptor for standard net/http.
func standardAuthzMiddleware(t *testing.T, authorizer declarative.Authorizer, resourceIdentifier string, action string) middleware.Middleware {
	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req interface{}) (interface{}, error) {
			t.Logf("[DEBUG] standardAuthzMiddleware: Starting authorization check")
			// For standard net/http, the context might be updated by previous middleware
			// We need to get the latest context from the http.Request if available
			var currentCtx context.Context

			if r, ok := req.(*http.Request); ok {
				currentCtx = r.Context()
				t.Logf("[DEBUG] standardAuthzMiddleware: Got context from http.Request")
			} else {
				currentCtx = ctx
				t.Logf("[DEBUG] standardAuthzMiddleware: Using provided context")
			}

			// Get the principal from context
			principal, ok := declarative.PrincipalFromContext(currentCtx)
			if !ok {
				errMsg := "principal not found in context"
				t.Logf("[ERROR] standardAuthzMiddleware: %s", errMsg)
				return nil, errors.Unauthorized("UNAUTHORIZED", errMsg)
			}

			t.Logf("[DEBUG] standardAuthzMiddleware: Found principal in context, ID: %s", principal.GetID())

			// Authorize the request
			t.Logf("[DEBUG] standardAuthzMiddleware: Authorizing principal %s for resource %s, action %s",
				principal.GetID(), resourceIdentifier, action)

			authorized, err := authorizer.Authorize(currentCtx, principal, resourceIdentifier, action)
			if err != nil {
				t.Logf("[ERROR] standardAuthzMiddleware: Authorization error: %v", err)
				return nil, err
			}

			if !authorized {
				errMsg := fmt.Sprintf("Principal %s is not authorized to perform action %s on resource %s",
					principal.GetID(), action, resourceIdentifier)
				t.Logf("[WARN] standardAuthzMiddleware: %s", errMsg)
				return nil, errors.Forbidden("FORBIDDEN", errMsg)
			}

			t.Logf("[DEBUG] standardAuthzMiddleware: Authorization successful")
			return handler(ctx, req)
		}
	}
}

// authnFilterFunc is a standard net/http middleware (FilterFunc) that performs authentication
// and injects the Principal into the http.Request's context.
func authnFilterFunc(t *testing.T, authenticator declarative.Authenticator, extractor declarative.CredentialExtractor) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			provider := impl.FromHTTPRequest(r)

			cred, err := extractor.Extract(r.Context(), provider) // Pass r.Context() here
			if err != nil {
				http.Error(w, errors.Unauthorized("CREDENTIAL_MISSING", err.Error()).Error(), http.StatusUnauthorized)
				return
			}

			principal, err := authenticator.Authenticate(r.Context(), cred)
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}

			newCtx := declarative.PrincipalWithContext(r.Context(), principal)
			next.ServeHTTP(w, r.WithContext(newCtx))
		})
	}
}

// authzFilterFunc is a standard net/http middleware (FilterFunc) that performs authorization.
func authzFilterFunc(t *testing.T, authorizer declarative.Authorizer, resourceIdentifier string, action string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get the latest context from the request, which might have been updated by authnFilterFunc
			ctx := r.Context()

			principal, ok := declarative.PrincipalFromContext(ctx)
			if !ok {
				http.Error(w, errors.Unauthorized("UNAUTHENTICATED", "principal not found in context, authentication required").Error(), http.StatusUnauthorized)
				return
			}

			allowed, err := authorizer.Authorize(ctx, principal, resourceIdentifier, action)
			if err != nil {
				http.Error(w, err.Error(), http.StatusForbidden) // Use Forbidden for authorization errors
				return
			}
			if !allowed {
				http.Error(w, errors.Forbidden("PERMISSION_DENIED", "principal not authorized for this resource/action").Error(), http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// TestServiceHTTP defines a simple HTTP service for Kratos.
type SeparatedTestServiceHTTP interface {
	TestCall(context.Context, *emptypb.Empty) (*emptypb.Empty, error)
}

// testServiceHTTPImpl implements TestServiceHTTP.
type SeparatedTestServiceHTTPImpl struct {
	testT *testing.T // Renamed from 't' to 'testT'
}

func (s *SeparatedTestServiceHTTPImpl) TestCall(ctx context.Context, req *emptypb.Empty) (*emptypb.Empty, error) {
	p, ok := declarative.PrincipalFromContext(ctx)
	assert.True(s.testT, ok, "Principal should be in Kratos HTTP context (native handler)")
	if ok {
		assert.Equal(s.testT, "separated-test-user", p.GetID())
	}
	return &emptypb.Empty{}, nil
}

func RegisterSeparatedTestServiceHTTPServer(s *kratoshttp.Server, srv SeparatedTestServiceHTTP) {
	r := s.Route("/")
	r.GET(separatedTestResource, separatedTestServiceCallHTTPHandler(srv))
}

func separatedTestServiceCallHTTPHandler(srv SeparatedTestServiceHTTP) func(ctx kratoshttp.Context) error {
	return func(ctx kratoshttp.Context) error {
		var in emptypb.Empty
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

// --- 3. Test Scenarios for Separated Middleware ---

func TestSeparatedMiddlewareIntegration(t *testing.T) {
	// --- Setup common components ---
	auth := &SeparatedMockAuthenticator{
		validToken: separatedValidToken,
		t:          t, // Pass the testing.T to the mock authenticator
	}
	authorizer := &SeparatedMockAuthorizer{} // Our mock authorizer
	extractor := impl.NewHeaderCredentialExtractor()

	// Use the CompositeAuthenticator
	compositeAuth := impl.NewCompositeAuthenticator(auth)

	// Create independent authentication and authorization middleware chains
	kratosAuthnChain := kratosAuthnMiddleware(compositeAuth, extractor)
	kratosAuthzChain := kratosAuthzMiddleware(authorizer, separatedTestResource, separatedTestAction)

	// Create standard middleware chains with the test logger
	standardAuthnChain := standardAuthnMiddleware(t, compositeAuth, extractor)
	standardAuthzChain := standardAuthzMiddleware(t, authorizer, separatedTestResource, separatedTestAction)

	// --- Scenario 1: Standard net/http Server ---
	t.Run("Standard net/http - Separated Middleware", func(t *testing.T) {
		finalHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, ok := declarative.PrincipalFromContext(r.Context())
			assert.True(t, ok, "Principal should be in context")
			if ok {
				assert.Equal(t, "separated-test-user", p.GetID())
			}
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, "OK")
		})

		// Create a standard http.Handler with our middleware chain
		middlewareAdapter := func(next http.Handler) http.Handler {
			// Create a handler that adapts the standard http.Handler to the middleware.Handler
			kratosHandler := func(ctx context.Context, req interface{}) (interface{}, error) {
				httpReq, ok := req.(*http.Request)
				if !ok {
					return nil, errors.BadRequest("INVALID_REQUEST", "expected *http.Request")
				}
				next.ServeHTTP(httptest.NewRecorder(), httpReq)
				return nil, nil
			}

			// Apply the authn and authz middleware
			handler := standardAuthnChain(standardAuthzChain(kratosHandler))

			// Return a new http.Handler that calls our chained handler
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, err := handler(r.Context(), r)
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

		// Test with valid token (Authn & Authz pass)
		t.Logf("\n=== Testing with valid token ===")
		t.Logf("Sending request to: %s", server.URL)
		t.Logf("Authorization header: Bearer %s", separatedValidToken)

		req, _ := http.NewRequest("GET", server.URL, nil)
		req.Header.Set(separatedAuthHeader, "Bearer "+separatedValidToken)

		// Log request details
		t.Logf("Request headers: %+v", req.Header)

		resp, err := server.Client().Do(req)
		if err != nil {
			t.Logf("Request failed: %v", err)
		} else {
			t.Logf("Response status: %d", resp.StatusCode)
			body, _ := io.ReadAll(resp.Body)
			t.Logf("Response body: %s", string(body))
			resp.Body.Close()
		}

		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// Test with invalid token (Authn fails)
		t.Logf("\n=== Testing with invalid token ===")
		req, _ = http.NewRequest("GET", server.URL, nil)
		req.Header.Set(separatedAuthHeader, "Bearer "+separatedInvalidToken)
		t.Logf("Sending request with invalid token: Bearer %s", separatedInvalidToken)

		resp, err = server.Client().Do(req)
		if err != nil {
			t.Logf("Request failed: %v", err)
		} else {
			t.Logf("Response status: %d", resp.StatusCode)
			body, _ := io.ReadAll(resp.Body)
			t.Logf("Response body: %s", string(body))
			resp.Body.Close()
		}

		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

		// Test with no token (Authn fails)
		t.Logf("\n=== Testing with no token ===")
		req, _ = http.NewRequest("GET", server.URL, nil)
		t.Logf("Sending request with no authorization header")

		resp, err = server.Client().Do(req)
		if err != nil {
			t.Logf("Request failed: %v", err)
		} else {
			t.Logf("Response status: %d", resp.StatusCode)
			body, _ := io.ReadAll(resp.Body)
			t.Logf("Response body: %s", string(body))
			resp.Body.Close()
		}

		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	// --- Scenario 2: Kratos HTTP Server ---
	t.Run("Kratos HTTP - Separated Middleware", func(t *testing.T) {
		srv := kratoshttp.NewServer(
			kratoshttp.Address("127.0.0.1:0"),
			kratoshttp.Middleware(kratosAuthnChain, kratosAuthzChain), // Chain authn and authz middleware
		)

		testService := &SeparatedTestServiceHTTPImpl{testT: t} // Updated field name
		RegisterSeparatedTestServiceHTTPServer(srv, testService)

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

		// Test with valid token (Authn & Authz pass)
		req, _ := http.NewRequest("GET", endpoint.String()+separatedTestResource, nil)
		req.Header.Set(separatedAuthHeader, "Bearer "+separatedValidToken)
		resp, err := client.Do(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()

		// Test with invalid token (Authn fails)
		req, _ = http.NewRequest("GET", endpoint.String()+separatedTestResource, nil)
		req.Header.Set(separatedAuthHeader, "Bearer "+separatedInvalidToken)
		resp, err = client.Do(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		resp.Body.Close()

		// Test with no token (Authn fails)
		req, _ = http.NewRequest("GET", endpoint.String()+separatedTestResource, nil)
		resp, err = client.Do(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		resp.Body.Close()
	})

	// --- Scenario 3: Kratos HTTP Server with http.HandlerFunc Context Propagation ---
	t.Run("Kratos HTTP - HandlerFunc Context Propagation - Separated Middleware", func(t *testing.T) {
		httpHandler := func(w http.ResponseWriter, r *http.Request) {
			p, ok := declarative.PrincipalFromContext(r.Context())
			assert.True(t, ok, "Principal should be in Kratos HTTP context (HandlerFunc) via FilterFunc")
			if ok {
				assert.Equal(t, "separated-test-user", p.GetID())
			}
			w.WriteHeader(http.StatusOK)
		}

		// Create a handler that adapts the standard http.Handler to the middleware.Handler
		kratosHandler := func(ctx context.Context, req interface{}) (interface{}, error) {
			httpReq, ok := req.(*http.Request)
			if !ok {
				return nil, errors.BadRequest("INVALID_REQUEST", "expected *http.Request")
			}
			// Create a response recorder to capture the response
			w := httptest.NewRecorder()
			// Create a new request with the context
			httpReq = httpReq.WithContext(ctx)
			// Call the http handler with the updated request
			httpHandler(w, httpReq)
			// Return the response status code and any error
			return nil, nil
		}

		// Apply the authn and authz middleware
		handler := kratosAuthnChain(kratosAuthzChain(kratosHandler))

		// Create a standard http.Handler that calls our chained handler
		wrappedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Call the handler with the request context
			resp, err := handler(r.Context(), r)

			// After the handler runs, check if we have a principal in the context
			if p, ok := declarative.PrincipalFromContext(r.Context()); ok {
				t.Logf("[DEBUG] Found principal in context: %s", p.GetID())
			} else {
				t.Logf("[DEBUG] No principal found in context")
			}

			// If we have a response from the handler, write it to the response writer
			if resp != nil {
				if respErr, ok := resp.(error); ok {
					t.Logf("[ERROR] Handler returned error: %v", respErr)
					http.Error(w, respErr.Error(), http.StatusInternalServerError)
				}
			}
			if err != nil {
				if se := errors.FromError(err); se != nil {
					http.Error(w, se.Message, int(se.Code))
				} else {
					http.Error(w, err.Error(), http.StatusInternalServerError)
				}
			}
		})

		srv := kratoshttp.NewServer(
			kratoshttp.Address("127.0.0.1:0"),
		)

		// Register routes with the Kratos server
		handleRequest := func(ctx kratoshttp.Context) error {
			// Create a response recorder to capture the response
			w := httptest.NewRecorder()
			// Create a new request with the context
			httpReq := ctx.Request().WithContext(ctx)
			// Call our wrapped handler
			wrappedHandler.ServeHTTP(w, httpReq)
			// Write the response back to the client
			for k, v := range w.Header() {
				ctx.Header().Set(k, v[0])
			}
			ctx.Blob(w.Code, "", w.Body.Bytes())
			return nil
		}

		// Register both root and /test paths
		srv.Route("/").GET("", handleRequest)
		srv.Route("/test").GET("", handleRequest)

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

		// Test with valid token (Authn & Authz pass)
		req, _ := http.NewRequest("GET", endpoint.String()+separatedTestResource, nil)
		req.Header.Set(separatedAuthHeader, "Bearer "+separatedValidToken)
		resp, err := client.Do(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()

		// Test with invalid token (Authn fails)
		req, _ = http.NewRequest("GET", endpoint.String()+separatedTestResource, nil)
		req.Header.Set(separatedAuthHeader, "Bearer "+separatedInvalidToken)
		resp, err = client.Do(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		resp.Body.Close()

		// Test with no token (Authn fails)
		req, _ = http.NewRequest("GET", endpoint.String()+separatedTestResource, nil)
		resp, err = client.Do(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		resp.Body.Close()
	})

	// --- Scenario 4: Kratos gRPC Server ---
	t.Run("Kratos gRPC - Separated Middleware", func(t *testing.T) {
		handler := func(ctx context.Context, req interface{}) (interface{}, error) {
			p, ok := declarative.PrincipalFromContext(ctx)
			assert.True(t, ok, "Principal should be in Kratos gRPC context")
			if ok {
				assert.Equal(t, "separated-test-user", p.GetID())
			}
			return &emptypb.Empty{}, nil
		}

		lis, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to listen: %v", err)
		}
		addr := lis.Addr().String()
		lis.Close()

		srv := kratosgrpc.NewServer(
			kratosgrpc.Address(addr),
			kratosgrpc.Middleware(kratosAuthnChain, kratosAuthzChain), // Chain authn and authz middleware
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

		// Test with valid token (Authn & Authz pass)
		ctxValid := metadata.NewOutgoingContext(context.Background(), metadata.Pairs(separatedAuthHeader, "Bearer "+separatedValidToken))
		var reply emptypb.Empty
		err = conn.Invoke(ctxValid, "/test.Service/TestCall", &emptypb.Empty{}, &reply)
		assert.NoError(t, err)

		// Test with invalid token (Authn fails)
		ctxInvalid := metadata.NewOutgoingContext(context.Background(), metadata.Pairs(separatedAuthHeader, "Bearer "+separatedInvalidToken))
		err = conn.Invoke(ctxInvalid, "/test.Service/TestCall", &emptypb.Empty{}, &reply)
		assert.Error(t, err)
		st, ok := status.FromError(err)
		assert.True(t, ok)
		assert.Equal(t, codes.Unauthenticated, st.Code())

		// Test with no token (Authn fails)
		ctxNoToken := context.Background()
		err = conn.Invoke(ctxNoToken, "/test.Service/TestCall", &emptypb.Empty{}, &reply)
		assert.Error(t, err)
		st, ok = status.FromError(err)
		assert.True(t, ok)
		assert.Equal(t, codes.Unauthenticated, st.Code())
	})
}
