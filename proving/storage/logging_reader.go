package storage

import (
	"io"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/log"
)

type loggingReader struct {
	io.Reader
	io.Closer
	message string
	key     string
	size    int64
	started bool
	n       atomic.Int64
	closed  atomic.Bool
}

func NewLoggingReader(r io.ReadCloser, message, key string, size int64) io.ReadCloser {
	return &loggingReader{
		Reader:  r,
		Closer:  r,
		message: message,
		key:     key,
		size:    size,
	}
}

func (p *loggingReader) Read(b []byte) (int, error) {
	if !p.started {
		p.started = true
		go func() {
			for !p.closed.Load() {
				n := p.n.Load()
				log.Info(p.message, "file", p.key, "current", n, "total", p.size, "percent", n*100/p.size)
				time.Sleep(10 * time.Second)
			}
		}()
	}
	n, err := p.Reader.Read(b)
	p.n.Add(int64(n))
	return n, err
}

func (p *loggingReader) Close() error {
	p.closed.Store(true)
	log.Info("Closed", "file", p.key, "current", p.n.Load(), "total", p.size)
	return p.Closer.Close()
}
