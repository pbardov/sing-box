package naivexhttp

import (
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUploadQueueReordersPackets(t *testing.T) {
	queue := newUploadQueue(4)
	require.NoError(t, queue.push(uploadPacket{seq: 1, payload: []byte("world")}))
	require.NoError(t, queue.push(uploadPacket{seq: 0, payload: []byte("hello")}))

	buffer := make([]byte, 16)
	n, err := queue.Read(buffer)
	require.NoError(t, err)
	require.Equal(t, "hello", string(buffer[:n]))

	n, err = queue.Read(buffer)
	require.NoError(t, err)
	require.Equal(t, "world", string(buffer[:n]))
}

func TestUploadQueuePartialRead(t *testing.T) {
	queue := newUploadQueue(4)
	require.NoError(t, queue.push(uploadPacket{seq: 0, payload: []byte("packet")}))

	buffer := make([]byte, 3)
	n, err := queue.Read(buffer)
	require.NoError(t, err)
	require.Equal(t, "pac", string(buffer[:n]))

	n, err = queue.Read(buffer)
	require.NoError(t, err)
	require.Equal(t, "ket", string(buffer[:n]))
}

func TestUploadQueueClose(t *testing.T) {
	queue := newUploadQueue(4)
	require.NoError(t, queue.Close())

	buffer := make([]byte, 16)
	_, err := queue.Read(buffer)
	require.ErrorIs(t, err, io.EOF)
	require.ErrorIs(t, queue.push(uploadPacket{seq: 0, payload: []byte("late")}), io.ErrClosedPipe)
}
