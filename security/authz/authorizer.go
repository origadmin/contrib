package authz

import (
	"context"
	"github.com/origadmin/contrib/security"
)

// RuleSpec 封装了一条待检查的授权规则的规格。
// 它是一个纯粹的数据容器，描述了授权检查所需的核心要素。
type RuleSpec struct {
	Domain   string // 代表项目或租户。可以为空。
	Resource string // 被访问的资源。
	Action   string // 要执行的操作。
	// Attributes 包含了与此规则相关的额外属性，例如资源的所有者、状态等。
	// 这使得 RuleSpec 能够承载更复杂的上下文信息，以支持 ABAC。
	Attributes security.Claims
}

// Authorizer 定义了核心的授权接口，用于对单个请求进行验证。
// 它通常在中间件中作为“守门员”使用。
type Authorizer interface {
	// Authorized 对单条规则规格进行检查。
	Authorized(ctx context.Context, p security.Principal, spec RuleSpec) (bool, error)
}
