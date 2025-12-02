// Package request implements the functions, types, and interfaces for the module.
package request

import (
	"net/http"

	"github.com/goexts/generic/maps"
	"google.golang.org/grpc/metadata"

	securityv1 "github.com/origadmin/contrib/api/gen/go/security/v1"
	"github.com/origadmin/contrib/security"
	metadataifaces "github.com/origadmin/runtime/interfaces/metadata"
)

// Metadata represents a collection of metadata key-value pairs.
// It implements both metadataifaces.Meta and the internal valueSource interface.
type Metadata map[string][]string

func (m Metadata) Append(key string, values ...string) {
	m[key] = append(m[key], values...)
}

func (m Metadata) Clone() metadataifaces.Meta {
	return maps.Clone(m)
}

func (m Metadata) GetAll() map[string][]string {
	return m
}

func (m Metadata) Values(key string) []string {
	return m[key]
}

func (m Metadata) Get(key string) string {
	if values := m.Values(key); len(values) > 0 {
		return values[0]
	}
	return ""
}

func (m Metadata) Set(key string, value string) {
	m[key] = []string{value}
}

// FromRequest creates Metadata from a security.Request provider.
func FromRequest(p security.Request) Metadata {
	meta := maps.Clone(p.GetAll())
	return meta
}

// FromHTTP creates Metadata from HTTP headers.
func FromHTTP(h http.Header) Metadata {
	return Metadata(maps.Clone(h))
}

// FromGRPC creates Metadata from gRPC metadata.
func FromGRPC(md metadata.MD) Metadata {
	return Metadata(maps.Clone(md))
}

// ToHTTP converts Metadata to HTTP headers.
func ToHTTP(m Metadata) http.Header {
	return http.Header(m)
}

// ToGRPC converts Metadata to gRPC metadata.
func ToGRPC(m Metadata) metadata.MD {
	return metadata.MD(m)
}

// ToProto converts the Metadata map to its Protobuf representation.
func (m Metadata) ToProto() map[string]*securityv1.MetaValue {
	protoMeta := make(map[string]*securityv1.MetaValue)
	for k, v := range m {
		protoMeta[k] = NewMetaValue(v...)
	}
	return protoMeta
}

// NewMetaValue creates a MetaValue protobuf message.
func NewMetaValue(values ...string) *securityv1.MetaValue {
	return &securityv1.MetaValue{
		Values: values,
	}
}

// FromProto creates Metadata from protobuf metadata.
func FromProto(protoMeta map[string]*securityv1.MetaValue) Metadata {
	m := make(Metadata, len(protoMeta))
	for k, v := range protoMeta {
		m[k] = v.Values
	}
	return m
}

var _ metadataifaces.Meta = Metadata(nil)
