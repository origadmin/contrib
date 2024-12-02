{{$svrType :=.ServiceType}}
{{$svrName :=.ServiceName}}

{{- range.MethodSets}}
	const {{$svrType}}_{{.OriginalName}}_FullOperation = "/{{$svrName}}/{{.OriginalName}}"
{{- end}}

type {{.ServiceType}}GINRPCServer interface {
{{- range.MethodSets}}
    {{- if ne .Comment ""}}
        {{.Comment}}
    {{- end}}
    {{.Name}}(*gin.Context, *{{.Request}})
{{- end}}
}

func Register{{.ServiceType}}GINRPCServer(router gins.IRouter, srv {{.ServiceType}}GINRPCServer) {
{{- range.Methods}}
	router.{{.Method}}("{{.Path}}", _{{$svrType}}_{{.Name}}{{.Num}}_GINRPC_Handler(srv))
{{- end}}
}

{{range.Methods}}
	func _{{$svrType}}_{{.Name}}{{.Num}}_GINRPC_Handler(srv {{$svrType}}GINRPCServer) func(ctx *gins.Context) {
	return func(ctx *gins.Context) {
	var in {{.Request}}
  {{- if.HasBody}}
		if err := gins.BindBody(ctx,&in{{.Body}}); err != nil {
		gins.ResultError(ctx,err)
		return
		}
  {{- end}}
	if err := gins.BindQuery(ctx,&in{{.Query}}); err != nil {
		gins.ResultError(ctx,err)
		return
	}
  {{- if.HasVars}}
		if err := gins.BindURI(ctx,&in{{.Vars}}); err != nil {
			gins.ResultError(ctx,err)
			return
		}
  {{- end}}
	gins.SetOperation(ctx, {{$svrType}}_{{.OriginalName}}_OperationName)
	srv.{{.Name}}(ctx, &in)
	}
	}
{{end}}
