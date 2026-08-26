package naivexhttp

import (
	"io"
	"net"
	"os"
	"sync"
	"time"
)

type splitConn struct {
	reader     io.ReadCloser
	writer     io.WriteCloser
	localAddr  net.Addr
	remoteAddr net.Addr
	onClose    func()
	closeOnce  sync.Once
}

func (c *splitConn) Read(buffer []byte) (int, error) {
	return c.reader.Read(buffer)
}

func (c *splitConn) Write(buffer []byte) (int, error) {
	return c.writer.Write(buffer)
}

func (c *splitConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		err = c.writer.Close()
		if readErr := c.reader.Close(); err == nil {
			err = readErr
		}
		if c.onClose != nil {
			c.onClose()
		}
	})
	return err
}

func (c *splitConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *splitConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *splitConn) SetDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *splitConn) SetReadDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *splitConn) SetWriteDeadline(t time.Time) error {
	return os.ErrInvalid
}

type responseWriterConn struct {
	access sync.Mutex
	done   chan struct{}
	writer io.Writer
	flush  func()
}

func newResponseWriterConn(writer io.Writer, flush func()) *responseWriterConn {
	return &responseWriterConn{
		done:   make(chan struct{}),
		writer: writer,
		flush:  flush,
	}
}

func (c *responseWriterConn) Write(buffer []byte) (int, error) {
	c.access.Lock()
	defer c.access.Unlock()
	select {
	case <-c.done:
		return 0, io.ErrClosedPipe
	default:
	}
	n, err := c.writer.Write(buffer)
	if err == nil && c.flush != nil {
		c.flush()
	}
	return n, err
}

func (c *responseWriterConn) Close() error {
	c.access.Lock()
	defer c.access.Unlock()
	select {
	case <-c.done:
	default:
		close(c.done)
	}
	return nil
}

func (c *responseWriterConn) Wait() <-chan struct{} {
	return c.done
}
