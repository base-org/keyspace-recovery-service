package storage

import (
	"io"
)

type Storage interface {
	Reader(key string) (io.ReadCloser, error)
	Writer(key string) (io.WriteCloser, error)
}
