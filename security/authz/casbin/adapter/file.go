// Package adapter implements the functions, types, and interfaces for the module.
package adapter

import (
	fileadapter "github.com/casbin/casbin/v3/persist/file-adapter"
)

func NewFile(path string) *fileadapter.Adapter {
	return fileadapter.NewAdapter(path)
}
