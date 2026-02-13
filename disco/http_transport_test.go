// Copyright IBM Corp. 2017, 2025

package disco

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestHedgedTransport_MultipleAttempts(t *testing.T) {
	var requestCount int32
	hedgeTimeout := 5 * time.Millisecond
	maxAttempts := 7

	// Create a slow test server that would require 3 hedged attempts to succeed
	// with the given timeouts.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)

		if count := atomic.LoadInt32(&requestCount); count >= 3 {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("success"))
			return
		}

		<-r.Context().Done()
	}))
	defer ts.Close()

	transport := newHedgedHTTPTransport(http.DefaultTransport, hedgeTimeout, maxAttempts)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, "GET", ts.URL, nil)

	start := time.Now()
	t.Log("Starting roundtrip")
	resp, err := transport.RoundTrip(req)
	duration := time.Since(start)

	if resp != nil && resp.Body != nil {
		t.Cleanup(func() {
			resp.Body.Close()
		})
	}

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	count := atomic.LoadInt32(&requestCount)
	var expectedAttempts int32 = 3 // With the given timings, we expect 3 attempts
	if count != expectedAttempts {
		t.Errorf("Expected %d requests to be made, but got %d", expectedAttempts, count)
	}

	t.Logf("Total requests: %d, Total duration: %v", count, duration)
}

func TestHedgedTransport_AllFail(t *testing.T) {
	var requestCount int32
	hedgeTimeout := 5 * time.Millisecond
	maxAttempts := 7

	// Create a slow test server that would require 3 hedged attempts to succeed
	// with the given timeouts.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		<-r.Context().Done()
	}))
	t.Cleanup(func() {
		ts.Close()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	transport := newHedgedHTTPTransport(http.DefaultTransport, hedgeTimeout, maxAttempts)
	req, _ := http.NewRequestWithContext(ctx, "GET", ts.URL, nil)
	start := time.Now()
	resp, err := transport.RoundTrip(req)
	duration := time.Since(start)

	if resp != nil && resp.Body != nil {
		resp.Body.Close()
		t.Errorf("Unexpected body in test response")
	}

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Expected context.DeadlineExceeded error, got %T", err)
	}

	count := atomic.LoadInt32(&requestCount)
	var expectedAttempts = int32(maxAttempts) // With the given timings, we expect 3 attempts
	if count != expectedAttempts {
		t.Errorf("Expected %d requests to be made, but got %d", expectedAttempts, count)
	}

	t.Logf("Total requests: %d, Total duration: %v", count, duration)
}

func TestHedgedTransport_LastResponseSucceeds(t *testing.T) {
	var requestCount int32
	hedgeTimeout := 5 * time.Millisecond
	maxAttempts := 7

	// Create a slow test server that would require 3 hedged attempts to succeed
	// with the given timeouts.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)

		if count := atomic.LoadInt32(&requestCount); count == int32(maxAttempts) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("success"))
			return
		}

		<-r.Context().Done()
	}))
	t.Cleanup(func() {
		ts.Close()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	transport := newHedgedHTTPTransport(http.DefaultTransport, hedgeTimeout, maxAttempts)
	req, _ := http.NewRequestWithContext(ctx, "GET", ts.URL, nil)
	start := time.Now()
	resp, err := transport.RoundTrip(req)
	duration := time.Since(start)

	if resp != nil && resp.Body != nil {
		resp.Body.Close()
	} else {
		t.Errorf("Expected a response body, got nil")
	}

	if err != nil {
		t.Fatalf("Expected no error, got %T", err)
	}

	count := atomic.LoadInt32(&requestCount)
	var expectedAttempts = int32(maxAttempts) // With the given timings, we expect 3 attempts
	if count != expectedAttempts {
		t.Errorf("Expected %d requests to be made, but got %d", expectedAttempts, count)
	}

	t.Logf("Total requests: %d, Total duration: %v", count, duration)
}

// contextAwareBody simulates the behavior of a real net/http response body:
// reads fail once the request context is canceled. In production, this happens
// because the underlying TCP connection is tied to the request context.
type contextAwareBody struct {
	ctx    context.Context
	data   []byte
	offset int
}

func (b *contextAwareBody) Read(p []byte) (int, error) {
	if err := b.ctx.Err(); err != nil {
		return 0, err
	}
	if b.offset >= len(b.data) {
		return 0, io.EOF
	}
	n := copy(p, b.data[b.offset:])
	b.offset += n
	return n, nil
}

func (b *contextAwareBody) Close() error {
	return nil
}

// slowBodyTransport is a fake RoundTripper that controls exactly which attempt
// succeeds. Attempts before successAfter block until their context is canceled
// (simulating a slow upstream). The attempt that matches successAfter returns
// a 200 with a context-aware body.
type slowBodyTransport struct {
	requestCount int32
	successAfter int32
}

func (t *slowBodyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	count := atomic.AddInt32(&t.requestCount, 1)

	if count >= t.successAfter {
		return &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Body: &contextAwareBody{
				ctx:  req.Context(),
				data: []byte("success"),
			},
		}, nil
	}

	<-req.Context().Done()
	return nil, req.Context().Err()
}

// TestHedgedTransport_BodyReadableAfterReturn demonstrates a bug found in
// hedgedTransport.RoundTrip: the shared context was canceled via defer before
// the caller has a chance to read the response body. Because the winning
// response's body is bound to that context, sometimes reading the body would
// fail with "context canceled".
func TestHedgedTransport_BodyReadableAfterReturn(t *testing.T) {
	transport := &slowBodyTransport{successAfter: 2}

	// 10ms hedge delay means the second attempt fires 10ms after the first.
	// 5 max attempts gives plenty of room (we only need 2).
	hedged := newHedgedHTTPTransport(transport, 10*time.Millisecond, 5)

	req, err := http.NewRequest("GET", "http://example.com/test", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	resp, err := hedged.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip returned error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	// This is where the bug manifests: by the time we read the body,
	// defer cancel() in hedgedTransport.RoundTrip has already fired,
	// canceling the context that the response body depends on.
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}

	if string(body) != "success" {
		t.Fatalf("expected body %q, got %q", "success", string(body))
	}
}
