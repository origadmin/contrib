package cors

import (
	"github.com/gin-gonic/contrib/cors"
	"github.com/gin-gonic/gin"

	"github.com/origadmin/toolkits/middlewares"
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

func WithCors(cfg *middlewares.CorsConfig) gin.HandlerFunc {
	if !cfg.Enabled {
		return func(ctx *gin.Context) {
			ctx.Next()
		}
	}

	allOrigins := true
	if len(cfg.AllowOrigins) > 0 && cfg.AllowOrigins[0] != corsMatchAll {
		allOrigins = false
	}

	return cors.New(cors.Config{
		AbortOnError:     false,
		AllowOriginFunc:  nil,
		AllowAllOrigins:  allOrigins,
		AllowedOrigins:   cfg.AllowOrigins,
		AllowedMethods:   cfg.AllowMethods,
		AllowedHeaders:   cfg.AllowHeaders,
		ExposedHeaders:   cfg.ExposeHeaders,
		AllowCredentials: cfg.AllowCredentials,
		MaxAge:           cfg.MaxAge.AsDuration(),
	})
}
