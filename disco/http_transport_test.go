// Copyright IBM Corp. 2017, 2025

package disco

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestHedgedTransport_MultipleAttempts(t *testing.T) {
	var requestCount int32
	hedgeTimeout := 50 * time.Millisecond
	serverSleep := 150 * time.Millisecond
	maxAttempts := 7

	// Create a slow test server that would require 3 hedged attempts to succeed
	// with the given timeouts.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)

		// Wait longer than the hedge timeout to trigger multiple attempts
		select {
		case <-time.After(serverSleep):
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "success")
		case <-r.Context().Done():
			// This demonstrates that cancellation is working!
			return
		}
	}))
	defer ts.Close()

	transport := newHedgedHTTPTransport(http.DefaultTransport, hedgeTimeout, maxAttempts)

	req, _ := http.NewRequestWithContext(t.Context(), "GET", ts.URL, nil)

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
