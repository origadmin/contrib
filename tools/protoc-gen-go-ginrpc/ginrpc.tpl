{{$svrType :=.ServiceType}}
{{$svrName :=.ServiceName}}

{{- range.MethodSets}}
	const {{$svrType}}_{{.OriginalName}}_FullOperation = "/{{$svrName}}/{{.OriginalName}}"
{{- end}}

type {{.ServiceType}}GINRPCAgentResponder interface {
		// Error returns a error
		Error(*gins.Context, int, error)
		// JSON returns a json data
		JSON(*gins.Context, int, any)
		// Any returns errors or any data
		Any(*gins.Context, int, any, error)
}

type {{.ServiceType}}GINRPCAgent interface {
		{{.ServiceType}}GINRPCAgentResponder
{{- range.MethodSets}}
    {{- if ne .Comment ""}}
        {{.Comment}}
    {{- end}}
    {{.Name}}(*gins.Context, *{{.Request}})
{{- end}}
}

func Register{{.ServiceType}}GINRPCAgent (router gins.IRouter, srv {{.ServiceType}}GINRPCAgent) {
{{- range.Methods}}
	router.{{.Method}}("{{.Path}}", _{{$svrType}}_{{.Name}}{{.Num}}_GINRPC_Handler(srv))
{{- end}}
}

{{range.Methods}}
	func _{{$svrType}}_{{.Name}}{{.Num}}_GINRPC_Handler(srv {{$svrType}}GINRPCAgent) gins.HandlerFunc {
	return func(ctx *gins.Context) {
	var in {{.Request}}
  {{- if.HasBody}}
		if err := gins.BindBody(ctx,&in{{.Body}}); err != nil {
		srv.Error(ctx, 400, err)
		return
		}
  {{- end}}
	if err := gins.BindQuery(ctx,&in{{.Query}}); err != nil {
		srv.Error(ctx, 400, err)
		return
	}
  {{- if.HasVars}}
		if err := gins.BindURI(ctx,&in{{.Vars}}); err != nil {
		srv.Error(ctx, 400, err)
			return
		}
  {{- end}}
	gins.SetOperation(ctx, {{$svrType}}_{{.OriginalName}}_OperationName)
	srv.{{.Name}}(ctx, &in)
	}
	}
{{end}}
