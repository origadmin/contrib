/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package filestore

// Manager defines the interface for managing the file system's namespace and structure.
type Manager interface {
	// CreateNode creates a new node in the index.
	CreateNode(node *Node) error

	// GetNode retrieves a node by its unique ID.
	GetNode(nodeID string) (*Node, error)

	// GetNodeByPath retrieves a node by its full path.
	GetNodeByPath(path string) (*Node, error)

	// UpdateNode updates an existing node's data.
	// This is used for operations like chmod, chown, or rename.
	UpdateNode(node *Node) error

	// DeleteNode removes a node from the index.
	// It should fail if trying to delete a non-empty directory.
	DeleteNode(nodeID string) error

	// ListChildren retrieves all immediate children of a directory node.
	ListChildren(parentID string) ([]*Node, error)

	// MoveNode moves a node to a new parent directory and/or new name.
	MoveNode(nodeID string, newParentID string, newName string) error
}
