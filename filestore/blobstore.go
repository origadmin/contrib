// Package filestore implements the functions, types, and interfaces for the module.
package filestore

type Blobstore interface {
	Write(data []byte) (string, error)
	Read(hash string) ([]byte, error)
	Delete(hash string) error
	Exists(hash string) (bool, error)
}
