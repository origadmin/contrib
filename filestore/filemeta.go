/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package filestore implements the functions, types, and interfaces for the module.
package filestore

import (
	"time"
)

type FileMeta interface {
	// CurrentVersion returns the version number of this metadata record.
	CurrentVersion() int32
	// Size returns the byte size of the file contents.
	Size() int64
	// ModTime returns when the contents of the file itself were last modified.
	ModTime() time.Time
	// GetEmbeddedData returns the raw byte data if the file content is embedded directly in the metadata.
	// It returns nil if the content is not embedded.
	GetEmbeddedData() []byte
	// GetShards returns a list of blob hashes if the file content is stored in external blobs (shards).
	// It returns nil if the content is embedded or the file is empty.
	GetShards() []string
}

// A FileInfo is a domain object that represents a fully managed file.
// It brings together the file's ID and its metadata.
type FileInfo struct {
	ID   string
	Meta FileMeta
}

type FileMetaVersion struct {
	Version int32 `msgpack:"v"`
}

func (f FileMetaVersion) CurrentVersion() int32 {
	return f.Version
}

type StoreMeta[T FileMeta] struct {
	Version int32 `json:"version" msgpack:"v"`
	Data    T     `json:"data" msgpack:"d"`
}

func (f StoreMeta[T]) CurrentVersion() int32 {
	return f.Version
}

func (f StoreMeta[T]) Size() int64 {
	return f.Data.Size()
}

func (f StoreMeta[T]) ModTime() time.Time {
	return f.Data.ModTime()
}

func (f StoreMeta[T]) GetEmbeddedData() []byte {
	return f.Data.GetEmbeddedData()
}

func (f StoreMeta[T]) GetShards() []string {
	return f.Data.GetShards()
}
