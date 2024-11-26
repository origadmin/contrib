/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package std

import (
	"net/http"
)

// BasicAuthHandler returns an HTTP handler function
// that performs basic authentication using the provided userid and password.
// It checks the request's basic authentication credentials
// and responds with a 401 Unauthorized status if the credentials are invalid.
func BasicAuthHandler(userid, passwd string, next http.Handler) http.HandlerFunc {
	return func(resp http.ResponseWriter, req *http.Request) {
		username, pwd, ok := req.BasicAuth()

		if !ok || !(username == userid && pwd == passwd) {
			resp.WriteHeader(http.StatusUnauthorized)
			_, _ = resp.Write([]byte("401 Unauthorized"))
			return
		}
		if next != nil {
			next.ServeHTTP(resp, req)
		}
	}
}
