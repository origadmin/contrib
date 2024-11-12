package logger

import (
	"os"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/go-kratos/kratos/v2/middleware/logging"

	"github.com/origadmin/toolkits/middlewares"
)

func Middleware(config *middlewares.LoggerConfig, logger log.Logger) (middleware.Middleware, error) {
	if logger == nil {
		// todo: init logger from config
		logger = log.NewStdLogger(os.Stdout)
	}

	// TODO: add metrics middleware
	return logging.Server(logger), nil
}

func NewLogger(config *middlewares.LoggerConfig) log.Logger {
	return log.NewStdLogger(os.Stdout)
}
