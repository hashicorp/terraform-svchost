// Copyright IBM Corp. 2017, 2025

package disco

import (
	"context"
	"io"
	"net/http"
	"sync"
	"time"
)

// DefaultUserAgent is the default User-Agent header value used in requests.
const DefaultUserAgent = "terraform-svchost/1.0"

// userAgentRoundTripper is an http.RoundTripper that adds a User-Agent header
// to requests.
type userAgentRoundTripper struct {
	innerRt   http.RoundTripper
	userAgent string
}

type result struct {
	resp   *http.Response
	cancel context.CancelFunc
}

// hedgedBodyWrapper is an io.ReadCloser that cancels the associated hedgedTransport
// context when closed, ensuring that any resources associated with the winning
// request are cleaned up when the user is done with the response.
type hedgedBodyWrapper struct {
	io.ReadCloser
	cancel context.CancelFunc
}

// hedgedTransport implements a hedged HTTP transport that sends multiple
// requests if a previous request takes too long, with a specified timeout
// between attempts.
// Note: As always, it's necessary to close any non-nil response body
// in order to avoid leaking resources. This is the mechanism by which
// the successful request context is finally canceled.
type hedgedTransport struct {
	// Transport is the underlying RT used to actually make the requests.
	transport http.RoundTripper
	// Timeout is the interval between initiating hedged requests.
	timeout time.Duration
	// MaxAttempts is the total number of requests (1 original + n-1 hedges).
	maxAttempts int
}

// newHedgedHTTPTransport creates a new hedgedTransport with the specified timings
func newHedgedHTTPTransport(transport http.RoundTripper, hedgeTimeout time.Duration, upTo int) http.RoundTripper {
	return &hedgedTransport{
		transport:   transport,
		timeout:     hedgeTimeout,
		maxAttempts: upTo,
	}
}

// newUserAgentTransport creates a new userAgentRoundTripper with the given ua string
func newUserAgentTransport(userAgent string, innerRt http.RoundTripper) http.RoundTripper {
	return &userAgentRoundTripper{
		innerRt:   innerRt,
		userAgent: userAgent,
	}
}

// RoundTrip implements the http.RoundTripper interface for hedgedTransport
// it sends the initial request immediately and then sends additional
// requests if previous ones take too long, returning the first successful
// response or the first error if all attempts fail.
func (ht *hedgedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	reqctx := req.Context()

	// Channel for receiving the first successful response
	results := make(chan *result, 1)

	// Buffered channel to track all possible errors. We only return an error if ALL attempts fail.
	errors := make(chan error, ht.maxAttempts)

	var (
		mu       sync.Mutex
		cancels  = make([]context.CancelFunc, ht.maxAttempts)
		finished bool
		firstErr error
	)

	abort := func() {
		mu.Lock()
		defer mu.Unlock()
		finished = true
		for _, c := range cancels {
			if c != nil {
				c()
			}
		}
	}

	spawn := func(idx int) {
		mu.Lock()
		subctx, cancel := context.WithCancel(reqctx)
		cancels[idx] = cancel
		mu.Unlock()

		go func(subctx context.Context, c context.CancelFunc, idx int) {
			spawnreq := req.Clone(subctx)
			resp, err := ht.transport.RoundTrip(spawnreq)

			if err != nil {
				errors <- err
				return
			}

			mu.Lock()
			if finished {
				// The main loop aborted OR another request already won.
				// We must close this body immediately to prevent a leak.
				mu.Unlock()
				if resp != nil && resp.Body != nil {
					resp.Body.Close()
				}
				return
			}

			finished = true

			// Cancel all other in-flight requests
			for j, otherCancel := range cancels {
				if otherCancel != nil && j != idx {
					otherCancel()
				}
			}
			mu.Unlock()

			results <- &result{resp: resp, cancel: c}
		}(subctx, cancel, idx)
	}

	spawned := 0
	errorsReceived := 0

	// Fire attempt 0 immediately
	spawn(spawned)
	spawned++

	// Centralized orchestration loop
	for {
		select {
		case <-reqctx.Done():
			abort()
			return nil, reqctx.Err()

		case res := <-results:
			res.resp.Body = &hedgedBodyWrapper{
				ReadCloser: res.resp.Body,
				cancel:     res.cancel,
			}
			return res.resp, nil

		case err := <-errors:
			errorsReceived++
			if firstErr == nil {
				firstErr = err
			}

			// Only return an error if ALL hedges failed
			if errorsReceived == ht.maxAttempts {
				abort()
				return nil, firstErr
			}

			// If a request fails, don't wait for the timer. Spawn the next hedge immediately.
			if spawned < ht.maxAttempts {
				spawn(spawned)
				spawned++
			}

		case <-time.After(ht.timeout):
			if spawned < ht.maxAttempts {
				spawn(spawned)
				spawned++
			}
		}
	}
}

func (w *hedgedBodyWrapper) Close() error {
	err := w.ReadCloser.Close()
	w.cancel() // Finally clean up the winner's context
	return err
}

// RoundTrip implements the http.RoundTripper interface for userAgentRoundTripper
func (rt *userAgentRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if _, ok := req.Header["User-Agent"]; !ok {
		req.Header.Set("User-Agent", rt.userAgent)
	}

	return rt.innerRt.RoundTrip(req)
}
