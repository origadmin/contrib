package cors

import (
	"net/http"

	"github.com/gorilla/handlers"

	configv1 "github.com/origadmin/toolkits/runtime/gen/go/config/v1"
)

const (
	corsOptionMethod              string = "OPTIONS"
	corsAllowOriginHeader         string = "Access-Control-Allow-Origin"
	corsExposeHeadersHeader       string = "Access-Control-Expose-Headers"
	corsMaxAgeHeader              string = "Access-Control-Max-Age"
	corsAllowMethodsHeader        string = "Access-Control-Allow-Methods"
	corsAllowHeadersHeader        string = "Access-Control-Allow-Headers"
	corsAllowCredentialsHeader    string = "Access-Control-Allow-Credentials"
	corsAllowPrivateNetworkHeader string = "Access-Control-Allow-Private-Network"
	corsRequestMethodHeader       string = "Access-Control-Request-Method"
	corsRequestHeadersHeader      string = "Access-Control-Request-Headers"
	corsRequestPrivateNetwork     string = "Access-Control-Request-Private-Network"
	corsOriginHeader              string = "Origin"
	corsVaryHeader                string = "Vary"
	corsMatchAll                  string = "*"
)

type FilterFunc = func(http.Handler) http.Handler

func WithCors(cfg *configv1.Cors) FilterFunc {
	opts := []handlers.CORSOption{
		handlers.AllowedOrigins(cfg.AllowOrigins),
		handlers.AllowedHeaders(cfg.AllowHeaders),
		handlers.AllowedMethods(cfg.AllowMethods),
		handlers.ExposedHeaders(cfg.ExposeHeaders),
		handlers.MaxAge(int(cfg.MaxAge.GetSeconds())),
	}
	if cfg.AllowCredentials {
		opts = append(opts, handlers.AllowCredentials())
	}
	if len(cfg.AllowOrigins) == 0 || cfg.AllowOrigins[0] == corsMatchAll {
		opts = append(opts, handlers.AllowedOriginValidator(allOrigins))
	}

	return handlers.CORS(opts...)
}

func allOrigins(origin string) bool {
	return true
}
