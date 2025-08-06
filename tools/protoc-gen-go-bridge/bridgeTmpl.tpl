{{$svrType := .ServiceType}}
{{$svrName := .ServiceName}}

{{- range .MethodSets}}
	const {{$svrType}}{{.OriginalName}}BridgeOperation = "/{{$svrName}}/{{.OriginalName}}"
{{- end}}

type {{.ServiceType}}BridgeServer interface {
{{- range .MethodSets}}
    {{- if ne .Comment ""}}
        {{.Comment}}
    {{- end}}
    {{.Name}}(context.Context, *{{.Request}}) (*{{.Reply}}, error)
{{- end}}
}

type {{.ServiceType}}Hooker interface {
{{- range .MethodSets}}
    {{$svrType}}{{.Name}}Hooker
{{- end}}
}

type {{.ServiceType}}HookedBridger interface {
		{{.ServiceType}}Hooker
		{{.ServiceType}}BridgeServer
}

{{- range .MethodSets}}
	type {{$svrType}}{{.Name}}Hooker interface {
		Prepare{{.Name}}(http.Context, *{{.Request}}) (context.Context, error)
		Complete{{.Name}}(http.Context,*{{.Request}}, *{{.Reply}}) error
	}
{{- end}}

func Register{{.ServiceType}}BridgeServer(s *http.Server, srv {{.ServiceType}}HookedBridger) {
r := s.Route("/")
{{- range .Methods}}
	r.{{.Method}}("{{.Path}}", _{{$svrType}}_{{.Name}}{{.Num}}_Bridge_Handler(srv))
{{- end}}
}

{{range .Methods}}
	func _{{$svrType}}_{{.Name}}{{.Num}}_Bridge_Handler(srv {{$svrType}}HookedBridger) func(ctx http.Context) error {
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

	newctx,err:=srv.Prepare{{.Name}}(ctx, &in)
	if err != nil {
	return err
	}
	out, err := h(newctx, &in)
	if err != nil {
	return err
	}
	return srv.Complete{{.Name}}(ctx,&in, out.(*{{.Reply}}))
	}
	}
{{end}}

// Unimplemented{{.ServiceType}}Hooked must be embedded to have
// forward compatible implementations.
//
// NOTE: this should be embedded by value instead of pointer to avoid a nil
// pointer dereference when methods are called.
type Unimplemented{{.ServiceType}}Hooked struct{}

{{range .MethodSets}}
	func (Unimplemented{{$svrType}}Hooked)Prepare{{.Name}}(ctx http.Context,in *{{.Request}}) (context.Context, error){
	return ctx, nil
	}

	func (Unimplemented{{$svrType}}Hooked)Complete{{.Name}}(ctx http.Context,in *{{.Request}},out *{{.Reply}}) error {
	return ctx.Result(200, out{{.ResponseBody}})
	}
{{end}}


func With{{.ServiceType}}Hook(h {{.ServiceType}}Hooker) func({{.ServiceType}}BridgeServer) {{.ServiceType}}HookedBridger {
return func(srv {{.ServiceType}}BridgeServer) {{.ServiceType}}HookedBridger {
return {{.ServiceType}}HookedBridge{ {{.ServiceType}}BridgeServer:srv, {{.ServiceType}}Hooker:h}
}
}

// {{.ServiceType}}HookedBridge is a bridge between the HTTP and gRPC implementations of {{.ServiceType}}.
// It implements the HTTP and gRPC implementations of {{.ServiceType}}.
// It forwards requests and responses between the two implementations.
type {{.ServiceType}}HookedBridge struct{
{{.ServiceType}}BridgeServer
{{.ServiceType}}Hooker
}

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

{{range.ExtMethodSets}}
	func (c *{{$svrType}}BridgeImpl) {{.Name}}(request *{{.Request}}, g grpc.ServerStreamingServer[{{.Reply}}]) error {
		stream, err := c.client.{{.Name}}(g.Context(), request)
		if err != nil {
			return err
		}
		for {
			rule, err := stream.Recv()
			if err == io.EOF {
				break
			}
			if err != nil {
				return status.Errorf(status.Code(err), "received stream error: %v", err)
			}
			if err := g.Send(rule); err != nil {
				return err
			}
		}
		return nil
	}
{{end}}
func (c *{{.ServiceType}}BridgeImpl) mustEmbedUnimplemented{{.ServiceType}}Server() {}

type {{.ServiceType}}GRPC2HTTPBridgeImpl struct {
client {{.ServiceType}}Client
}

func New{{.ServiceType}}GRPC2HTTP(client grpc.ClientConnInterface) {{.ServiceType}}HTTPServer {
		return &{{.ServiceType}}GRPC2HTTPBridgeImpl{client:New{{.ServiceType}}Client(client)}
}

{{range .MethodSets}}
	func (c *{{$svrType}}GRPC2HTTPBridgeImpl) {{.Name}}(ctx context.Context, in *{{.Request}}) (*{{.Reply}}, error) {
			return c.client.{{.Name}}(ctx, in)
	}
{{end}}

type {{.ServiceType}}HTTP2GRPCBridgeImpl struct {
		client {{.ServiceType}}HTTPClient
}

func New{{.ServiceType}}HTTP2GRPC(client *http.Client) {{.ServiceType}}Server {
		return &{{.ServiceType}}HTTP2GRPCBridgeImpl{client:New{{.ServiceType}}HTTPClient(client)}
}

{{range .MethodSets}}
	func (c *{{$svrType}}HTTP2GRPCBridgeImpl) {{.Name}}(ctx context.Context, in *{{.Request}}) (*{{.Reply}}, error) {
	return c.client.{{.Name}}(ctx, in)
	}
{{end}}

{{range.ExtMethodSets}}
func (c *{{$svrType}}HTTP2GRPCBridgeImpl) {{.Name}}(request *{{.Request}}, g grpc.ServerStreamingServer[{{.Reply}}]) error {
	return status.Errorf(codes.Unimplemented, "StreamRules not implemented")
}
{{end}}

func (c *{{.ServiceType}}HTTP2GRPCBridgeImpl) mustEmbedUnimplemented{{.ServiceType}}Server() {}
