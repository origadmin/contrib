package principal

// PropagationType defines the type of transport for which the security context
// should be propagated. This allows middleware to adapt its behavior based on
// the underlying transport mechanism (e.g., Kratos HTTP, Kratos gRPC, Native gRPC, etc.).
type PropagationType int

const (
	// PropagationTypeUnknown indicates an unknown or unspecified propagation type.
	PropagationTypeUnknown PropagationType = iota
	// PropagationTypeKratos is for propagation within Kratos HTTP transport.
	PropagationTypeKratos
	// PropagationTypeGRPC is for propagation within native gRPC transport (without Kratos transport layer).
	PropagationTypeGRPC
	// PropagationTypeHTTP is for propagation within native HTTP transport (without Kratos transport layer).
	PropagationTypeHTTP
)

// String returns the string representation of the PropagationType.
func (pt PropagationType) String() string {
	switch pt {
	case PropagationTypeKratos:
		return "Kratos"
	case PropagationTypeGRPC:
		return "GRPC"
	case PropagationTypeHTTP:
		return "HTTP"
	default:
		return "Unknown"
	}
}
