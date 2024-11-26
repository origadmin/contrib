/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package gin

import (
	stdhttp "net/http"

	"github.com/gin-gonic/gin"

	"github.com/origadmin/toolkits/errors/httperr"
)

// BasicAuthHandler returns an HTTP handler function
// that performs basic authentication using the provided userid and password.
// It checks the request's basic authentication credentials
// and responds with a 401 Unauthorized status if the credentials are invalid.
func BasicAuthHandler(userid, passwd string, next func(ctx *gin.Context)) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		username, pwd, ok := ctx.Request.BasicAuth()

		if !ok || !(username == userid && pwd == passwd) {
			_ = ctx.AbortWithError(stdhttp.StatusUnauthorized, httperr.Unauthorized("Unauthorized"))
			return
		}

		if next != nil {
			next(ctx)
		}
	}
}
