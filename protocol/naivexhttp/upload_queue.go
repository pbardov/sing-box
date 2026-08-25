package naivexhttp

import (
	"container/heap"
	"errors"
	"io"
	"sync"
)

type uploadPacket struct {
	payload []byte
	seq     uint64
}

type uploadQueue struct {
	packets    chan uploadPacket
	heap       uploadHeap
	nextSeq    uint64
	maxPackets int
	closed     chan struct{}
	closeOnce  sync.Once
}

func newUploadQueue(maxPackets int) *uploadQueue {
	if maxPackets <= 0 {
		maxPackets = defaultMaxBufferedPosts
	}
	return &uploadQueue{
		packets:    make(chan uploadPacket, maxPackets),
		heap:       uploadHeap{},
		maxPackets: maxPackets,
		closed:     make(chan struct{}),
	}
}

func (q *uploadQueue) push(packet uploadPacket) error {
	select {
	case <-q.closed:
		return io.ErrClosedPipe
	default:
	}
	select {
	case q.packets <- packet:
		return nil
	case <-q.closed:
		return io.ErrClosedPipe
	}
}

func (q *uploadQueue) Close() error {
	q.closeOnce.Do(func() {
		close(q.closed)
	})
	return nil
}

func (q *uploadQueue) Read(buffer []byte) (int, error) {
	if len(buffer) == 0 {
		return 0, nil
	}
	for {
		select {
		case <-q.closed:
			return 0, io.EOF
		default:
		}
		if len(q.heap) == 0 {
			select {
			case packet := <-q.packets:
				heap.Push(&q.heap, packet)
			case <-q.closed:
				return 0, io.EOF
			}
		}
		packet := heap.Pop(&q.heap).(uploadPacket)
		switch {
		case packet.seq == q.nextSeq:
			n := copy(buffer, packet.payload)
			if n < len(packet.payload) {
				packet.payload = packet.payload[n:]
				heap.Push(&q.heap, packet)
			} else {
				q.nextSeq++
			}
			return n, nil
		case packet.seq > q.nextSeq:
			if len(q.heap) > q.maxPackets {
				return 0, errors.New("packet queue is too large")
			}
			heap.Push(&q.heap, packet)
			select {
			case nextPacket := <-q.packets:
				heap.Push(&q.heap, nextPacket)
			case <-q.closed:
				return 0, io.EOF
			}
		}
	}
}

type uploadHeap []uploadPacket

func (h uploadHeap) Len() int           { return len(h) }
func (h uploadHeap) Less(i, j int) bool { return h[i].seq < h[j].seq }
func (h uploadHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *uploadHeap) Push(x any) {
	*h = append(*h, x.(uploadPacket))
}

func (h *uploadHeap) Pop() any {
	old := *h
	n := len(old)
	packet := old[n-1]
	*h = old[:n-1]
	return packet
}
