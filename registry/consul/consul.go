/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package consul implements the functions, types, and interfaces for the module.
package consul

const Type = "consul"

//go:generate adptool .
//go:adapter:package github.com/go-kratos/kratos/contrib/registry/consul/v2
