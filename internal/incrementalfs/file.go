package incrementalfs

import (
	"context"
	"errors"
	"io"
	"os"
)

// ReadFile reads an exact regular, non-symlink file through a bounded
// descriptor while observing ctx between reads.
func ReadFile(ctx context.Context, path string, maximum int64) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || maximum < 0 {
		return nil, errors.New("bounded file is unavailable")
	}
	expected, err := os.Lstat(path) // #nosec G703 -- caller-selected local diagnostic file.
	if err != nil || !expected.Mode().IsRegular() || expected.Mode()&os.ModeSymlink != 0 || expected.Size() < 0 || expected.Size() > maximum {
		return nil, errors.New("bounded file is unavailable")
	}
	file, err := os.Open(path) // #nosec G304,G703 -- validated caller-selected regular file.
	if err != nil {
		return nil, errors.New("bounded file is unavailable")
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(expected, opened) || opened.Size() < 0 || opened.Size() > maximum {
		return nil, errors.New("bounded file changed during open")
	}
	body, err := io.ReadAll(io.LimitReader(contextReader{ctx: ctx, reader: file}, maximum+1))
	if err != nil || int64(len(body)) != opened.Size() || int64(len(body)) > maximum {
		return nil, errors.New("bounded file changed during read")
	}
	return body, nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader contextReader) Read(buffer []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(buffer)
}
