/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package gins is a gin extension package.
package gins

import "github.com/go-kratos/kratos/v2/log"

type infoLogger struct {
	Logger log.Logger
}

func (l *infoLogger) Write(p []byte) (n int, err error) {
	err = l.Logger.Log(log.LevelInfo, "msg", string(p))
	return
}

type errLogger struct {
	Logger log.Logger
}

func (l *errLogger) Write(p []byte) (n int, err error) {
	err = l.Logger.Log(log.LevelError, "msg", string(p))
	return
}
