package filestore

import (
	"io"
)

// Receipt 代表一次成功的内容写入操作的最终结果。
// 它是一个不可变的只读对象，作为操作成功的“收据”。
type Receipt struct {
	ContentID string
	FileMeta  FileMeta
}

// Writer 定义了流式写入内容的接口
type Writer interface {
	io.Writer
	io.Closer
	// Commit 是写入流程的最终步骤。它会完成所有数据的持久化（如写入最后的块、生成并存储元数据）。
	// 只有当所有操作都成功时，它才会返回一个包含结果的 Receipt。
	// 如果过程中发生任何错误，它将返回 error 并确保清理所有临时资源。
	Commit() (*Receipt, error)
	// Abort 中断写入操作并清理所有已创建的临时资源（如blobs）。
	Abort() error
}

// Assembler is responsible for assembling file content from metadata and blob storage.
type Assembler interface {
	// NewReader creates an io.Reader for the given FileMeta.
	// It uses the blobStore to fetch data chunks if necessary.
	NewReader(fileMeta FileMeta) (io.Reader, error)

	// WriteContent processes the content from the reader, stores it (either embedded or as sharded blobs),
	// and returns the content ID and the generated FileMeta object.
	WriteContent(r io.Reader, size int64) (contentID string, fileMeta FileMeta, err error)

	// NewWriter 创建一个新的流式写入器
	NewWriter(r io.Reader) (Writer, error)
}
