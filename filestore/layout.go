/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package filestore provides a generic interface for storage layouts.
package filestore

// ShardedStorage defines the interface for a storage system
// that stores data in a sharded directory structure based on an ID.
type ShardedStorage interface {
	// Write saves the data for a given ID.
	// It handles the creation of subdirectories and writing the file.
	Write(id string, data []byte) error

	// Read retrieves the data for a given ID.
	Read(id string) ([]byte, error)

	// Exists checks if data exists for a given ID.
	Exists(id string) (bool, error)

	// Delete removes the data for a given ID.
	// It can also optionally remove empty parent directories.
	Delete(id string) error

	// GetPath returns the full file path for a given ID without accessing the file.
	GetPath(id string) (string, error)
}
