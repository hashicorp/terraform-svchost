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
	hedgeTimeout := 50 * time.Millisecond
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

	req, _ := http.NewRequestWithContext(context.Background(), "GET", ts.URL, nil)

	start := time.Now()
	resp, err := transport.RoundTrip(req)
	duration := time.Since(start)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	defer resp.Body.Close()

	count := atomic.LoadInt32(&requestCount)
	var expectedAttempts int32 = 3 // With the given timings, we expect 3 attempts
	if count != expectedAttempts {
		t.Errorf("Expected %d requests to be made, but got %d", expectedAttempts, count)
	}

	t.Logf("Total requests: %d, Total duration: %v", count, duration)
}

func TestHedgedTransport_5XXErrors(t *testing.T) {
	var requestCount int32
	hedgeTimeout := 50 * time.Millisecond
	maxAttempts := 7

	// Create a slow test server that would require 3 hedged attempts to succeed
	// with the given timeouts, except this time it returns 5xx errors instead of timing out.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)

		if count := atomic.LoadInt32(&requestCount); count >= 3 {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("success"))
			return
		}

		w.WriteHeader(http.StatusGatewayTimeout)
		w.Write([]byte("temporary server error"))
	}))
	defer ts.Close()

	transport := newHedgedHTTPTransport(http.DefaultTransport, hedgeTimeout, maxAttempts)

	req, _ := http.NewRequestWithContext(context.Background(), "GET", ts.URL, nil)

	start := time.Now()
	resp, err := transport.RoundTrip(req)
	duration := time.Since(start)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	defer resp.Body.Close()

	count := atomic.LoadInt32(&requestCount)
	var expectedAttempts int32 = 3 // With the given timings, we expect 3 attempts
	if count != expectedAttempts {
		t.Errorf("Expected %d requests to be made, but got %d", expectedAttempts, count)
	}

	t.Logf("Total requests: %d, Total duration: %v", count, duration)
}

// TestHedgedTransport_ResponseBodyReadable verifies that the response body
// can be fully read after RoundTrip returns.
//
// This is a regression test for a bug where RoundTrip's defer cancel()
// cancels the shared context that all hedged request clones use. Go's HTTP
// transport tears down connections whose request context is cancelled, so
// if the body hasn't been fully received yet the caller's io.ReadAll fails
// with "context canceled".
//
// The server uses chunked encoding with a delay between chunks so the full
// body is NOT sitting in the kernel's TCP receive buffer when RoundTrip
// returns. Without the delay, the body is often already buffered and the
// read wins the race against the teardown goroutine — hiding the bug.
func TestHedgedTransport_ResponseBodyReadable(t *testing.T) {
	expectedBody := `{"modules.v1": "https://example.com/v1/modules/"}`

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		flusher := w.(http.Flusher)
		// Send partial body — enough for the transport to return response
		// headers, but the caller still needs the rest.
		w.Write([]byte(expectedBody[:20]))
		flusher.Flush()
		// Delay ensures the second chunk arrives AFTER defer cancel() has
		// fired and the teardown goroutine has closed the connection.
		time.Sleep(50 * time.Millisecond)
		w.Write([]byte(expectedBody[20:]))
		flusher.Flush()
	}))
	defer ts.Close()

	transport := newHedgedHTTPTransport(http.DefaultTransport, 500*time.Millisecond, 3)

	req, _ := http.NewRequestWithContext(context.Background(), "GET", ts.URL, nil)
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected RoundTrip error: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body after RoundTrip returned: %v", err)
	}
	if string(body) != expectedBody {
		t.Fatalf("unexpected body %q; want %q", string(body), expectedBody)
	}
}

func TestHedgedTransport_NoResponseEver(t *testing.T) {
	var requestCount int32
	hedgeTimeout := 30 * time.Millisecond
	maxAttempts := 3

	// Create a slow test server that would require 3 hedged attempts to succeed
	// with the given timeouts.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		<-r.Context().Done()
	}))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	transport := newHedgedHTTPTransport(http.DefaultTransport, hedgeTimeout, maxAttempts)
	req, _ := http.NewRequestWithContext(ctx, "GET", ts.URL, nil)
	start := time.Now()
	resp, err := transport.RoundTrip(req)
	duration := time.Since(start)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Expected context.DeadlineExceeded error, got %T", err)
	}

	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}

	count := atomic.LoadInt32(&requestCount)
	var expectedAttempts = int32(maxAttempts) // With the given timings, we expect 3 attempts
	if count != expectedAttempts {
		t.Errorf("Expected %d requests to be made, but got %d", expectedAttempts, count)
	}

	t.Logf("Total requests: %d, Total duration: %v", count, duration)
}
