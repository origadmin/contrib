package logger

import (
	"os"

	"github.com/go-kratos/kratos/v2/middleware/logging"

	configv1 "github.com/origadmin/toolkits/runtime/gen/go/config/v1"
	"github.com/origadmin/toolkits/runtime/log"
	"github.com/origadmin/toolkits/runtime/middleware"
)

func Middleware(config *configv1.Logger, logger log.Logger) (middleware.Middleware, error) {
	if logger == nil {
		// todo: init logger from config
		logger = log.NewStdLogger(os.Stdout)
	}

	// TODO: add metrics middleware
	return logging.Server(logger), nil
}

func NewLogger(config *configv1.Logger) log.Logger {
	return log.NewStdLogger(os.Stdout)
}
