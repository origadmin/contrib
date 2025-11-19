package filestore

// Store defines the interface for a low-level, persistent key-value store for metadata objects.
type Store interface {
	// Create persists a new FileMeta object using a pre-determined, content-derived ID.
	// The caller is responsible for generating the correct ID.
	Create(id string, fileMeta FileMeta) error
	// Get retrieves a FileMeta object by its ID. It must handle different versions for backward compatibility.
	Get(id string) (FileMeta, error)
	// Exists checks if a FileMeta object with the given ID exists.
	Exists(id string) (bool, error)
	// Update overwrites an existing FileMeta object.
	Update(id string, fileMeta FileMeta) (FileMeta, error)
	// Delete removes a FileMeta object by its ID.
	Delete(id string) error
	// Migrate migrates a FileMeta object from a previous version to the current version.
	Migrate(id string) (FileMeta, error)
	// CurrentVersion returns the version number used for writing new metadata.
	CurrentVersion() int
}

// Batcher defines an optional interface for stores that support efficient batch operations.
// A type that implements Store can also choose to implement Batcher.
type Batcher interface {
	// BatchGet retrieves multiple FileMeta objects by their IDs. It must handle different versions for backward compatibility.
	BatchGet(ids []string) (map[string]FileMeta, error)
	// BatchUpdate overwrites multiple existing FileMeta objects.
	BatchUpdate(fileMetas map[string]FileMeta) error
}
