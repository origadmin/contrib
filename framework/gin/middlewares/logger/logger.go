package logger

import (
	"os"

	"github.com/go-kratos/kratos/v2/middleware/logging"

	"github.com/origadmin/toolkits/runtime/config"
	"github.com/origadmin/toolkits/runtime/log"
	"github.com/origadmin/toolkits/runtime/middleware"
)

func Middleware(config *config.Logger, logger log.Logger) (middleware.Middleware, error) {
	if logger == nil {
		// todo: init logger from config
		logger = log.NewStdLogger(os.Stdout)
	}

	// TODO: add metrics middleware
	return logging.Server(logger), nil
}

func NewLogger(config *config.Logger) log.Logger {
	return log.NewStdLogger(os.Stdout)
}
