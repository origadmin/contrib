/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package filestore

import (
	"io/fs"
	"time"
)

var (
	// ErrNodeNotFound is returned when a node is not found in the index.
	ErrNodeNotFound = fs.ErrNotExist
)

// Node represents a single entry in the file system index.
// It can be a file, a directory, or other types like a symlink.
type Node struct {
	// --- Common Metadata ---
	// These fields are present for all node types.

	NodeID   string      // Unique identifier for this node (e.g., a UUID). This is the primary key.
	ParentID string      // NodeID of the parent directory. The root directory's ParentID can be itself or a special value.
	Name     string      // Name of the node within its parent directory (e.g., "document.txt", "images").
	NodeType NodeType    // Type of the node (e.g., File, Directory, Symlink).
	Mode     fs.FileMode // Permissions and mode bits.
	OwnerID  string      // User ID of the owner.
	GroupID  string      // Group ID of the owner.
	Atime    time.Time   // Last access time.
	Mtime    time.Time   // Last modification time of the node itself (e.g., rename, permission change).
	Ctime    time.Time   // Creation time of the node.

	// --- Type-Specific Data ---
	// This data depends on the NodeType.

	// For NodeType = File:
	// MetaHash is the hash/ID of the FileMeta object in the Meta Store.
	// This links the index entry to the file's content and detailed metadata.
	MetaHash string `json:"meta_hash,omitempty"`

	// For NodeType = Symlink:
	Target string `json:"target,omitempty"` // The path the symbolic link points to.
}

type NodeType int

const (
	File      NodeType = iota // A regular file.
	Directory                 // A directory.
	Symlink                   // A symbolic link.
)
