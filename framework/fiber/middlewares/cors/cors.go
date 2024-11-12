package cors

import (
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"

	"github.com/origadmin/toolkits/runtime/config"
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

func WithCors(cfg *config.Cors) fiber.Handler {
	if !cfg.Enabled {
		return func(ctx *fiber.Ctx) error {
			return ctx.Next()
		}
	}

	allOrigins := allOrigins
	if len(cfg.AllowOrigins) > 0 && cfg.AllowOrigins[0] != corsMatchAll {
		allOrigins = nil
	}

	//if allOrigins && cfg.AllowCredentials {
	//	panic("[CORS] Insecure setup, 'AllowCredentials' is set to true, and 'AllowOrigins' is set to a wildcard.")
	//}

	return cors.New(cors.Config{
		AllowOriginsFunc: allOrigins,
		AllowOrigins:     strings.Join(cfg.AllowOrigins, ","),
		AllowMethods:     strings.Join(cfg.AllowMethods, ","),
		AllowHeaders:     strings.Join(cfg.AllowHeaders, ","),
		ExposeHeaders:    strings.Join(cfg.ExposeHeaders, ","),
		AllowCredentials: cfg.AllowCredentials,
		MaxAge:           int(cfg.MaxAge.GetSeconds()),
	})
}

func allOrigins(origin string) bool {
	return true
}
