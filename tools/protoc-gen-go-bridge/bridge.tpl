{{$svrType := .ServiceType}}
{{$svrName := .ServiceName}}

{{- range .MethodSets}}
	const {{$svrType}}{{.OriginalName}}BridgeOperation = "/{{$svrName}}/{{.OriginalName}}"
{{- end}}

type {{.ServiceType}}Bridger interface {
{{- range .MethodSets}}
    {{- if ne .Comment ""}}
        {{.Comment}}
    {{- end}}
    {{.Name}}(context.Context, *{{.Request}}) (*{{.Reply}}, error)
{{- end}}
}

type {{.ServiceType}}BridgeHooker interface {
{{.ServiceType}}Bridger
{{- range .MethodSets}}
    {{- if ne .Comment ""}}
        {{.Comment}}
    {{- end}}
    Before{{.Name}}(http.Context, *{{.Request}}) (context.Context, error)
    {{.Name}}Result(http.Context,*{{.Request}}, *{{.Reply}}) error
{{- end}}
}

func Register{{.ServiceType}}Bridger(s *http.Server, srv {{.ServiceType}}Bridger) {
r := s.Route("/")
		hook, ok := srv.({{.ServiceType}}BridgeHooker)
    if !ok {
			hook = Unimplemented{{.ServiceType}}Bridger{ {{.ServiceType}}Bridger:srv}
		}
{{- range .Methods}}
	r.{{.Method}}("{{.Path}}", _{{$svrType}}_{{.Name}}{{.Num}}_Bridge_Handler(hook))
{{- end}}
}

{{range .Methods}}
	func _{{$svrType}}_{{.Name}}{{.Num}}_Bridge_Handler(srv {{$svrType}}BridgeHooker) func(ctx http.Context) error {
	return func(ctx http.Context) error {
	var in {{.Request}}
  {{- if .HasBody}}
		if err := ctx.Bind(&in{{.Body}}); err != nil {
		return err
		}
  {{- end}}
	if err := ctx.BindQuery(&in); err != nil {
	return err
	}
  {{- if .HasVars}}
		if err := ctx.BindVars(&in); err != nil {
		return err
		}
  {{- end}}
	http.SetOperation(ctx,Operation{{$svrType}}{{.OriginalName}})
	h := ctx.Middleware(func(ctx context.Context, req interface{}) (interface{}, error) {
	return srv.{{.Name}}(ctx, req.(*{{.Request}}))
	})

	newctx,err:=srv.Before{{.Name}}(ctx, &in)
	if err != nil {
	return err
	}
	out, err := h(newctx, &in)
	if err != nil {
	return err
	}
	return srv.{{.Name}}Result(ctx,&in, out.(*{{.Reply}}))
	}
	}
{{end}}

// Unimplemented{{.ServiceType}}Bridger must be embedded to have
// forward compatible implementations.
//
// NOTE: this should be embedded by value instead of pointer to avoid a nil
// pointer dereference when methods are called.
type Unimplemented{{.ServiceType}}Bridger struct{
{{.ServiceType}}Bridger
}

{{range .MethodSets}}
func (Unimplemented{{$svrType}}Bridger)Before{{.Name}}(ctx http.Context,in *{{.Request}}) (context.Context, error){
	return ctx, nil
}

func (Unimplemented{{$svrType}}Bridger){{.Name}}Result(ctx http.Context,in *{{.Request}},out *{{.Reply}}) error {
	return ctx.Result(200, out{{.ResponseBody}})
}
{{end}}

type {{.ServiceType}}HTTPBridgeImpl struct {
		client {{.ServiceType}}HTTPClient
}


func New{{.ServiceType}}HTTPBridge(client *http.Client) {{.ServiceType}}HTTPServer {
		return &{{.ServiceType}}HTTPBridgeImpl{client:New{{.ServiceType}}HTTPClient(client)}
}

{{range .MethodSets}}
	func (c *{{$svrType}}HTTPBridgeImpl) {{.Name}}(ctx context.Context, in *{{.Request}}) (*{{.Reply}}, error) {
	   return c.client.{{.Name}}(ctx, in)
	}
{{end}}

type {{.ServiceType}}BridgeImpl struct {
		client {{.ServiceType}}Client
}

func New{{.ServiceType}}Bridge(client grpc.ClientConnInterface) {{.ServiceType}}Server {
return &{{.ServiceType}}BridgeImpl{client:New{{.ServiceType}}Client(client)}
}

{{range .MethodSets}}
	func (c *{{$svrType}}BridgeImpl) {{.Name}}(ctx context.Context, in *{{.Request}}) (*{{.Reply}}, error) {
			return c.client.{{.Name}}(ctx, in)
	}
{{end}}

func (c *{{.ServiceType}}BridgeImpl) mustEmbedUnimplemented{{.ServiceType}}Server() {}