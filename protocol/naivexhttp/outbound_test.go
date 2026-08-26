//go:build with_naive_outbound

package naivexhttp

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPacketUploadWriterCoalescesPayloads(t *testing.T) {
	uploads := make(chan string, 2)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		uploads <- string(body)
		writer.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	outbound := testPacketUploadOutbound(t, server.URL, 16, 6, 50*time.Millisecond, 1)
	uploadWriter := newPacketUploadWriter(context.Background(), outbound, "session")
	_, err := uploadWriter.Write([]byte("abc"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = uploadWriter.Write([]byte("def"))
	if err != nil {
		t.Fatal(err)
	}

	select {
	case payload := <-uploads:
		if payload != "abcdef" {
			t.Fatalf("unexpected payload: %q", payload)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for upload")
	}
}

func TestPacketUploadWriterSplitsAtCoalesceLimit(t *testing.T) {
	uploads := make(chan string, 4)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		uploads <- string(body)
		writer.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	outbound := testPacketUploadOutbound(t, server.URL, 16, 4, 0, 1)
	uploadWriter := newPacketUploadWriter(context.Background(), outbound, "session")
	_, err := uploadWriter.Write([]byte("abcdef"))
	if err != nil {
		t.Fatal(err)
	}

	for _, expected := range []string{"abcd", "ef"} {
		select {
		case payload := <-uploads:
			if payload != expected {
				t.Fatalf("unexpected payload: got %q, expected %q", payload, expected)
			}
		case <-time.After(time.Second):
			t.Fatalf("timeout waiting for upload %q", expected)
		}
	}
}

func TestPacketUploadWriterAllowsConcurrentPosts(t *testing.T) {
	var active atomic.Int32
	var reachedOnce sync.Once
	reachedConcurrency := make(chan struct{})
	releaseRequests := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, err := io.ReadAll(request.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		if active.Add(1) == 2 {
			reachedOnce.Do(func() {
				close(reachedConcurrency)
			})
		}
		defer active.Add(-1)
		<-releaseRequests
		writer.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	outbound := testPacketUploadOutbound(t, server.URL, 16, 0, 0, 2)
	uploadWriter := newPacketUploadWriter(context.Background(), outbound, "session")
	_, err := uploadWriter.Write([]byte("first"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = uploadWriter.Write([]byte("second"))
	if err != nil {
		t.Fatal(err)
	}

	select {
	case <-reachedConcurrency:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for concurrent uploads")
	}
	close(releaseRequests)
	err = uploadWriter.Close()
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-uploadWriter.done:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for upload writer shutdown")
	}
}

func testPacketUploadOutbound(t *testing.T, rawURL string, maxUploadSize int, coalesceBytes int, coalesceDelay time.Duration, maxConcurrentPosts int) *Outbound {
	t.Helper()
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	parsedURL.Path = "/"
	return &Outbound{
		http1:               true,
		httpClient:          http.DefaultClient,
		baseURL:             *parsedURL,
		extraHeaders:        map[string]string{},
		maxUploadSize:       maxUploadSize,
		uploadCoalesceBytes: coalesceBytes,
		uploadCoalesceDelay: coalesceDelay,
		maxConcurrentPosts:  maxConcurrentPosts,
		postAccess:          make(chan struct{}, maxConcurrentPosts),
	}
}
