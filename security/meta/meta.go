package meta

import (
	"maps"
	"net/http"

	"google.golang.org/grpc/metadata"

	"github.com/origadmin/contrib/security"
	securityv1 "github.com/origadmin/contrib/security/api/gen/go/config/v1"
	metadataifaces "github.com/origadmin/runtime/interfaces/metadata" // Updated path
)

type Meta map[string][]string

func (m Meta) Append(key string, values ...string) {
	m[key] = append(m[key], values...)
}

func (m Meta) Clone() metadataifaces.Meta { // Updated usage
	return maps.Clone(m)
}

func (m Meta) GetAll() map[string][]string {
	return m
}

func (m Meta) Values(key string) []string {
	return m[key]
}

func (m Meta) Get(key string) string {
	if values := m.Values(key); len(values) > 0 {
		return values[0]
	}
	return ""
}

func (m Meta) Set(key string, value string) {
	m[key] = []string{value}
}

func FromProvider(p security.Request) Meta {
	meta := maps.Clone(p.GetAll())
	return meta
}

func FromHTTPHeader(h http.Header) Meta {
	return Meta(maps.Clone(h))
}

// ToProto converts the Meta map to its Protobuf representation (map<string, MetaValue>).
func (m Meta) ToProto() map[string]*securityv1.MetaValue {
	protoMeta := make(map[string]*securityv1.MetaValue)
	for k, v := range m {
		protoMeta[k] = Values(v...)
	}
	return protoMeta
}

func FromGRPCHeader(md metadata.MD) Meta {
	return Meta(maps.Clone(md))
}

func ToHTTPHeader(m Meta) http.Header {
	return http.Header(m)
}

func ToGRPCHeader(m Meta) metadata.MD {
	return metadata.MD(m)
}

func Values(values ...string) *securityv1.MetaValue {
	return &securityv1.MetaValue{
		Values: values,
	}
}

func FromProtoMeta(protoMeta map[string]*securityv1.MetaValue) Meta {
	m := make(Meta, len(protoMeta))
	for k, v := range protoMeta {
		m[k] = v.Values
	}
	return m
}

var _ metadataifaces.Meta = Meta(nil) // Updated usage
