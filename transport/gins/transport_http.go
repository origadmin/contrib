/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package gins is a gin extension package.
package gins

import (
	"github.com/go-kratos/kratos/v2/transport"
	transhttp "github.com/go-kratos/kratos/v2/transport/http"
	"github.com/go-kratos/kratos/v2/transport/http/binding"
)

// SupportPackageIsVersion1 These constants should not be referenced from any other code.
const SupportPackageIsVersion1 = transhttp.SupportPackageIsVersion1

type (
	// Kind is transport kind
	Kind = transport.Kind
	// Client is an HTTP client.
	Client = transhttp.Client
	// CallOption configures a Call before it starts or extracts information from
	// a Call after it completes.
	CallOption = transhttp.CallOption
)

// Operation is serviceMethod call option
func Operation(operation string) CallOption {
	return transhttp.OperationCallOption{Operation: operation}
}

// PathTemplate is http path template
func PathTemplate(pattern string) CallOption {
	return transhttp.PathTemplateCallOption{Pattern: pattern}
}

// EncodeURL encode proto message to url path.
func EncodeURL(pathTemplate string, msg interface{}, needQuery bool) string {
	return binding.EncodeURL(pathTemplate, msg, needQuery)
}
