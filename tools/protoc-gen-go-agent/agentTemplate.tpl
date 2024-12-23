{{$svrType :=.ServiceType}}
{{$svrName :=.ServiceName}}

type {{.ServiceType}}Agent interface {
{{- range.MethodSets}}
    {{- if ne .Comment ""}}
        {{.Comment}}
    {{- end}}
    {{.Name}}(http.Context, *{{.Request}}) (*{{.Reply}}, error)
{{- end}}
}

func Register{{.ServiceType}}Agent (s *http.Server, srv {{.ServiceType}}Agent) {
	r := s.Route("/")
{{- range.Methods}}
	r.{{.Method}}("{{.Path}}", _{{$svrType}}_{{.Name}}{{.Num}}_Agent_Handler(srv))
{{- end}}
}

{{range.Methods}}
	func _{{$svrType}}_{{.Name}}{{.Num}}_Agent_Handler(srv {{$svrType}}Agent) http.HandlerFunc {
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
			h := ctx.Middleware(func(_ context.Context, req interface{}) (interface{}, error) {
			return srv.{{.Name}}(ctx, req.(*{{.Request}}))
			})
			out, err := h(ctx, &in)
			if err != nil {
			return err
			}
			if out == nil {
			return nil
			}
			reply := out{{.ResponseBody}}
			return ctx.Result(200, reply)
	}
	}
{{end}}
