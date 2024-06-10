package storage

import (
	"fmt"
	"io"
	"os"
)

type FileStorage struct {
	path string
}

func NewFileStorage(path string) Storage {
	return &FileStorage{path: path}
}

func (f *FileStorage) Reader(key string) (io.ReadCloser, error) {
	return os.Open(f.filename(key))
}

func (f *FileStorage) Writer(key string) (io.WriteCloser, error) {
	return os.Create(f.filename(key))
}

func (f *FileStorage) filename(vkHash string) string {
	return fmt.Sprintf("%s/%s", f.path, vkHash)
}
