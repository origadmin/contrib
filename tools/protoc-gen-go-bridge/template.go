/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package main

import (
	"bytes"
	_ "embed"
	"strings"
	"text/template"
)

//go:embed bridgeTmpl.tpl
var bridge string

type serviceDesc struct {
	ServiceType        string // Greeter
	ServiceName        string // helloworld.Greeter
	Metadata           string // api/helloworld/helloworld.proto
	Methods            []*methodDesc
	Prefix             string
	HasHTTPBindings    bool // If true, generate HTTP-related code (interfaces, structs)
	HasRoutableMethods bool // If true, generate Register... function with routes
}

type methodDesc struct {
	// method
	Name         string
	OriginalName string // The parsed original name
	Num          int
	Request      string
	Reply        string
	Comment      string
	// http_rule
	Path         string
	ClientPath   string
	Method       string
	HasVars      bool
	Vars         string
	HasQuery     bool
	Query        string
	HasBody      bool
	Body         string
	ResponseBody string

	// grpc_rule
	Streaming bool
}

func (s *serviceDesc) execute() string {
	buf := new(bytes.Buffer)
	tmpl, err := template.New("bridge").Parse(strings.TrimSpace(bridge))
	if err != nil {
		panic(err)
	}
	if err := tmpl.Execute(buf, s); err != nil {
		panic(err)
	}
	return strings.Trim(buf.String(), "\r\n")
}
