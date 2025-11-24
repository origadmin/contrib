package principal

import (
	"encoding/json"
	"fmt"

	"google.golang.org/protobuf/types/known/structpb"

	securityv1 "github.com/origadmin/contrib/api/gen/go/security/v1"
	"github.com/origadmin/contrib/security"
)

// --- concretePrincipal Implementation ---

// concretePrincipal is a concrete implementation of the security.Principal interface.
type concretePrincipal struct {
	id          string
	roles       []string
	permissions []string
	scopes      map[string]bool
	claims      security.Claims // Use security.Claims
}

func (p *concretePrincipal) GetID() string              { return p.id }
func (p *concretePrincipal) GetRoles() []string         { return p.roles }
func (p *concretePrincipal) GetPermissions() []string   { return p.permissions }
func (p *concretePrincipal) GetScopes() map[string]bool { return p.scopes }
func (p *concretePrincipal) GetClaims() security.Claims { return p.claims } // Use security.Claims

func (p *concretePrincipal) Export() *securityv1.Principal {
	return &securityv1.Principal{
		Id:          p.GetID(),
		Roles:       p.GetRoles(),
		Permissions: p.GetPermissions(),
		Scopes:      p.GetScopes(),
		Claims:      p.claims.Export(),
	}
}

// --- defaultClaims Implementation ---

// defaultClaims is a concrete implementation of the security.Claims interface.
type defaultClaims struct {
	data map[string]*structpb.Value
}

// Get retrieves a claim by key and returns it as a native Go type (any).
// It handles all data types including scalars, lists, and nested objects.
func (c *defaultClaims) Get(key string) (any, bool) {
	claimValue, ok := c.data[key]
	if !ok {
		return nil, false
	}
	// The AsInterface method recursively converts the structpb.Value to a native Go type.
	// This replaces the large manual switch statement, simplifying the logic immensely.
	// - structpb.StringValue -> string
	// - structpb.NumberValue -> float64
	// - structpb.BoolValue   -> bool
	// - structpb.NullValue   -> nil
	// - structpb.StructValue -> map[string]any
	// - structpb.ListValue   -> []any
	return claimValue.AsInterface(), true
}

func (c *defaultClaims) GetString(key string) (string, bool) {
	val, ok := c.data[key]
	if !ok || val == nil {
		return "", false
	}
	if s, isString := val.Kind.(*structpb.Value_StringValue); isString {
		return s.StringValue, true
	}
	return "", false
}

func (c *defaultClaims) GetInt64(key string) (int64, bool) {
	val, ok := c.data[key]
	if !ok || val == nil {
		return 0, false
	}
	if n, isNumber := val.Kind.(*structpb.Value_NumberValue); isNumber {
		return int64(n.NumberValue), true
	}
	return 0, false
}

func (c *defaultClaims) GetFloat64(key string) (float64, bool) {
	val, ok := c.data[key]
	if !ok || val == nil {
		return 0, false
	}
	if n, isNumber := val.Kind.(*structpb.Value_NumberValue); isNumber {
		return n.NumberValue, true
	}
	return 0, false
}

func (c *defaultClaims) GetBool(key string) (bool, bool) {
	val, ok := c.data[key]
	if !ok || val == nil {
		return false, false
	}
	if b, isBool := val.Kind.(*structpb.Value_BoolValue); isBool {
		return b.BoolValue, true
	}
	return false, false
}

func (c *defaultClaims) GetStringSlice(key string) ([]string, bool) {
	val, ok := c.data[key]
	if !ok || val == nil {
		return nil, false
	}
	if l, isList := val.Kind.(*structpb.Value_ListValue); isList {
		strSlice := make([]string, 0, len(l.ListValue.Values))
		for _, item := range l.ListValue.Values {
			if s, isString := item.Kind.(*structpb.Value_StringValue); isString {
				strSlice = append(strSlice, s.StringValue)
			} else {
				return nil, false
			}
		}
		return strSlice, true
	}
	return nil, false
}

func (c *defaultClaims) GetMap(key string) (map[string]any, bool) {
	val, ok := c.data[key]
	if !ok || val == nil {
		return nil, false
	}
	if s, isStruct := val.Kind.(*structpb.Value_StructValue); isStruct {
		return s.StructValue.AsMap(), true
	}
	return nil, false
}

func (c *defaultClaims) UnmarshalValue(key string, target any) error {
	val, ok := c.data[key]
	if !ok || val == nil {
		return fmt.Errorf("claim with key '%s' not found or is nil", key)
	}

	if s, isStruct := val.Kind.(*structpb.Value_StructValue); isStruct {
		m := s.StructValue.AsMap()
		jsonData, err := json.Marshal(m)
		if err != nil {
			return fmt.Errorf("failed to marshal claim '%s' to JSON: %w", key, err)
		}
		if err := json.Unmarshal(jsonData, target); err != nil {
			return fmt.Errorf("failed to unmarshal claim '%s' into target type: %w", key, err)
		}
		return nil
	}
	return fmt.Errorf("claim with key '%s' is not a struct type", key)
}

func (c *defaultClaims) Export() map[string]*structpb.Value {
	exportedClaims := make(map[string]*structpb.Value, len(c.data))
	for k, v := range c.data {
		exportedClaims[k] = v
	}
	return exportedClaims
}

// ClaimEncoder defines an interface for custom claim encoders.
// Users can implement this to provide custom logic for converting Go types to structpb.Value.
type ClaimEncoder interface {
	// Encode attempts to convert a Go value to a *structpb.Value.
	// It returns the converted value, a boolean indicating if it handled the conversion,
	// and an error if the conversion failed.
	Encode(key string, value any) (*structpb.Value, bool, error)
}

// convertToGoValueToStructpbValue converts a Go native type to a *structpb.Value.
// It handles basic types, slices of strings, and maps to structpb.Struct.
func convertToGoValueToStructpbValue(value any) (*structpb.Value, error) {
	switch v := value.(type) {
	case string:
		return structpb.NewStringValue(v), nil
	case int:
		return structpb.NewNumberValue(float64(v)), nil
	case int32:
		return structpb.NewNumberValue(float64(v)), nil
	case int64:
		return structpb.NewNumberValue(float64(v)), nil
	case bool:
		return structpb.NewBoolValue(v), nil
	case float32:
		return structpb.NewNumberValue(float64(v)), nil
	case float64:
		return structpb.NewNumberValue(v), nil
	case []string:
		listValues := make([]*structpb.Value, len(v))
		for i, s := range v {
			listValues[i] = structpb.NewStringValue(s)
		}
		return structpb.NewListValue(&structpb.ListValue{Values: listValues}), nil
	case []any:
		listValues := make([]*structpb.Value, len(v))
		for i, item := range v {
			innerClaimValue, err := convertToGoValueToStructpbValue(item)
			if err != nil {
				return nil, err
			}
			listValues[i] = innerClaimValue
		}
		return structpb.NewListValue(&structpb.ListValue{Values: listValues}), nil
	case map[string]any:
		structVal, err := structpb.NewStruct(v)
		if err != nil {
			return nil, fmt.Errorf("failed to convert map to structpb.Struct: %w", err)
		}
		return structpb.NewStructValue(structVal), nil
	case nil:
		return structpb.NewNullValue(), nil
	default:
		return nil, fmt.Errorf("unsupported claim type: %T", value)
	}
}

// --- Factory and Constructors ---

// NewClaims is a factory function that creates a standard Claims object from a raw map.
// It validates and normalizes the data, converting Go native types into structpb.Value protobuf messages.
// Custom encoders can be provided to handle specific types or override default conversion logic.
func NewClaims(rawData map[string]any, encoders ...ClaimEncoder) (security.Claims, error) { // Use security.Claims
	claimsData := make(map[string]*structpb.Value)

	if rawData == nil {
		return &defaultClaims{data: claimsData}, nil
	}

	for key, value := range rawData {
		var claimValue *structpb.Value
		var err error
		handled := false

		// Try custom encoders first
		for _, encoder := range encoders {
			claimValue, handled, err = encoder.Encode(key, value)
			if err != nil {
				return nil, fmt.Errorf("custom encoder for key '%s' failed: %w", key, err)
			}
			if handled {
				break
			}
		}

		if !handled {
			claimValue, err = convertToGoValueToStructpbValue(value)
			if err != nil {
				return nil, fmt.Errorf("failed to convert claim for key '%s': %w", key, err)
			}
		}
		claimsData[key] = claimValue
	}
	return &defaultClaims{data: claimsData}, nil
}

// New creates a new security.Principal instance.
func New(id string, roles, permissions []string, scopes map[string]bool, claims security.Claims) security.Principal { // Use security.Principal and security.Claims
	if scopes == nil {
		scopes = make(map[string]bool)
	}
	if claims == nil {
		claims, _ = NewClaims(nil)
	}
	return &concretePrincipal{
		id:          id,
		roles:       roles,
		permissions: permissions,
		scopes:      scopes,
		claims:      claims,
	}
}

// FromProto converts a *securityv1.Principal Protobuf message to a security.Principal.
func FromProto(protoP *securityv1.Principal) (security.Principal, error) { // Use security.Principal
	if protoP == nil {
		return nil, nil
	}

	claimsData := make(map[string]*structpb.Value)
	for key, claimValue := range protoP.GetClaims() {
		claimsData[key] = claimValue
	}

	claims := &defaultClaims{data: claimsData}

	return New(protoP.GetId(), protoP.GetRoles(), protoP.GetPermissions(), protoP.GetScopes(), claims), nil
}
