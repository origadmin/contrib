{{$svrType :=.ServiceType}}
{{$svrName :=.ServiceName}}

{{- range.MethodSets}}
	const {{$svrType}}_{{.OriginalName}}_OperationName = "/{{$svrName}}/{{.OriginalName}}"
{{- end}}

type {{.ServiceType}}GINSServer interface {
{{- range.MethodSets}}
    {{- if ne .Comment ""}}
        {{.Comment}}
    {{- end}}
    {{.Name}}(context.Context, *{{.Request}}) (*{{.Reply}}, error)
{{- end}}
}

func Register{{.ServiceType}}GINSServer(router gins.IRouter, srv {{.ServiceType}}GINSServer) {
{{- range.Methods}}
	router.{{.Method}}("{{.Path}}", _{{$svrType}}_{{.Name}}{{.Num}}_GIN_Handler(srv))
{{- end}}
}

{{range.Methods}}
	func _{{$svrType}}_{{.Name}}{{.Num}}_GIN_Handler(srv {{$svrType}}GINSServer) gins.HandlerFunc {
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
		newCtx := gins.NewContext(ctx)
		reply, err := srv.{{.Name}}(newCtx, &in)
		if err != nil {
			gins.ResultError(ctx,err)
			return
		}
		gins.ResultJSON(ctx,200, reply{{.ResponseBody}})
		return
	}
}
{{end}}

type {{.ServiceType}}GINSClient interface {
{{- range.MethodSets}}
    {{.Name}}(ctx context.Context, req *{{.Request}}, opts ...gins.CallOption) (rsp *{{.Reply}}, err error)
{{- end}}
}

type {{.ServiceType}}GINSClientImpl struct{
cc *gins.Client
}

func New{{.ServiceType}}GINSClient (client *gins.Client) {{.ServiceType}}GINSClient {
return &{{.ServiceType}}GINSClientImpl{client}
}

{{range.MethodSets}}
func (c *{{$svrType}}GINSClientImpl) {{.Name}}(ctx context.Context, in *{{.Request}}, opts ...gins.CallOption) (*{{.Reply}}, error) {
	var out {{.Reply}}
	pattern := "{{.ClientPath}}"
	path := gins.EncodeURL(pattern, in, {{not .HasBody}})
	opts = append(opts, gins.Operation({{$svrType}}_{{.OriginalName}}_OperationName))
	opts = append(opts, gins.PathTemplate(pattern))
  {{if.HasBody -}}
		err := c.cc.Invoke(ctx, "{{.Method}}", path, in{{.Body}}, &out{{.ResponseBody}}, opts...)
  {{else -}}
		err := c.cc.Invoke(ctx, "{{.Method}}", path, nil, &out{{.ResponseBody}}, opts...)
  {{end -}}
	if err != nil {
		return nil, err
	}
	return &out, nil
}
{{end}}
