package authz

import (
	"context"
	"github.com/origadmin/contrib/security"
)

// PermissionQuerier 定义了批量查询权限的接口。
// 这通常被专门的 API 端点用于 UI 渲染或后端批量处理。
type PermissionQuerier interface {
	// FilterAuthorized 对一个规格列表进行批量过滤，返回允许操作的子集。
	FilterAuthorized(ctx context.Context, p security.Principal, specs []RuleSpec) ([]RuleSpec, error)

	// FilterAuthorizedResources 过滤给定资源列表，返回 Principal 有权限访问的资源。
	// specTemplate 提供了一个 RuleSpec 模板，其中 Resource 字段将被忽略，
	// 授权引擎将根据 Resource 列表和模板中的 Domain/Action/Attributes 进行判断。
	FilterAuthorizedResources(ctx context.Context, p security.Principal, specTemplate RuleSpec, resources []string) ([]string, error)

	// FilterAuthorizedActions 过滤给定动作列表，返回 Principal 有权限执行的动作。
	// specTemplate 提供了一个 RuleSpec 模板，其中 Action 字段将被忽略。
	FilterAuthorizedActions(ctx context.Context, p security.Principal, specTemplate RuleSpec, actions []string) ([]string, error)

	// FilterAuthorizedDomains 过滤给定域列表，返回 Principal 有权限访问的域。
	// specTemplate 提供了一个 RuleSpec 模板，其中 Domain 字段将被忽略。
	FilterAuthorizedDomains(ctx context.Context, p security.Principal, specTemplate RuleSpec, domains []string) ([]string, error)
}
