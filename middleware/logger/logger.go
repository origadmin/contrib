/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package logger

import (
	"os"

	"github.com/go-kratos/kratos/v2/middleware/logging"
	logger "github.com/origadmin/slog-kratos"
	"github.com/origadmin/toolkits/slogx"

	configv1 "github.com/origadmin/runtime/gen/go/config/v1"
	"github.com/origadmin/runtime/log"
	"github.com/origadmin/runtime/middleware"
	"github.com/origadmin/toolkits/slogx"
)

func Middleware(cfg *configv1.Logger, l log.Logger) (middleware.Middleware, error) {
	if cfg == nil && l == nil {
		// todo: init l from config
		l = log.NewStdLogger(os.Stdout)
		return logging.Server(l), nil
	}

	nlog := slogx.New(FromConfig(cfg))
	l = logger.NewLogger(logger.WithLogger(nlog))
	return logging.Server(l), nil
}

func FromConfig(cfg *configv1.Logger) slogx.Setting {
	return func(option *slogx.Option) {
		//option.OutputPath = cfg.Path
		//option.Format = cfg.Format
		//option.TimeLayout = cfg.TimeLayout
		//option.Console = cfg.Console
		//option.Level = cfg.Level
		//option.ReplaceAttr = cfg.ReplaceAttr
		//option.AddSource = cfg.AddSource
		//option.LumberjackLogger = cfg.Lumberjack
		//option.DevConfig = cfg.Dev
		//option.NoColor = cfg.NoColor
		//option.Default = cfg.Default
	}
}
