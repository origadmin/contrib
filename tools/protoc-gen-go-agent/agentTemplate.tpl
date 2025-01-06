{{$svrType :=.ServiceType}}
{{$svrName :=.ServiceName}}

type {{.ServiceType}}Agent interface {
{{- range.MethodSets}}
    {{- if ne .Comment ""}}
        {{.Comment}}
    {{- end}}
    {{.Name}}(context.Context, *{{.Request}}) (*{{.Reply}}, error)
{{- end}}
}

{{range.Methods}}
	func _{{$svrType}}_{{.Name}}{{.Num}}_HTTPAgent_Handler(srv {{$svrType}}Agent) http.HandlerFunc {
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
	cctx := agent.NewHTTPContext(ctx, ctx)
	out, err := h(cctx, &in)
	if err != nil {
	return err
	}
	reply := out.(*{{.Reply}})
	if reply == nil {
	return nil
	}
	return ctx.Result(200, reply)
	}
	}
{{end}}

func Register{{.ServiceType}}Agent (ag agent.HTTPAgent, srv {{.ServiceType}}Agent) {
r := ag.Route()
{{- range.Methods}}
	r.{{.Method}}("{{.Path}}", _{{$svrType}}_{{.Name}}{{.Num}}_HTTPAgent_Handler(srv))
{{- end}}
}



