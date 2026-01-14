package security

import (
	"context"
)

// SkipChecker defines the function signature for determining whether to skip a middleware.
// It takes a context.Context and a Request, returning true if the middleware should be skipped.
//
// Decrypted: use Skipper instead
type SkipChecker = Skipper

type Skipper func(ctx context.Context, req Request) bool
