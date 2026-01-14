// Copyright IBM Corp. 2017, 2025

package disco

import (
	"context"
	"net/http"
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

// hedgedTransport implements a hedged HTTP transport that sends multiple
// requests if a previous request takes too long, with a specified timeout
// between attempts.
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
func (ht *hedgedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// We use a shared context to cancel all outstanding requests
	// once the first one returns successfully.
	ctx, cancel := context.WithCancel(req.Context())
	defer cancel()

	type result struct {
		res *http.Response
		err error
	}

	// Buffer the channel to prevent goroutine leaks.
	results := make(chan result, ht.maxAttempts)

	runAttempt := func() {
		outReq := req.Clone(ctx)
		resp, err := ht.transport.RoundTrip(outReq)

		// handle the error case downstream
		select {
		case results <- result{resp, err}:
		case <-ctx.Done():
			// If context is canceled, someone else won.
			// Ensure we don't leak the response body.
			if resp != nil && resp.Body != nil {
				resp.Body.Close()
			}
		}
	}
	go runAttempt()
	var lastErr error
	started := 1
	received := 0

	for {
		var timeout <-chan time.Time

		// if we haven't started all attempts, use ht.timeout.
		// if we have, wait indefinitely (effectively until context cancel).
		if started < ht.maxAttempts {
			timeout = time.After(ht.timeout)
		}
		select {
		case res := <-results:
			received++
			// Retry on error (no response) or 5xx
			if res.err == nil && res.res.StatusCode < 500 {
				return res.res, nil
			}
			// Don't leak response bodies
			if res.res != nil && res.res.Body != nil {
				res.res.Body.Close()
			}
			lastErr = res.err
			// If all attempts we started have failed AND we've reached the limit
			if received == ht.maxAttempts {
				return res.res, lastErr
			}
		case <-timeout:
			started++
			go runAttempt()
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
	}
}

// RoundTrip implements the http.RoundTripper interface for userAgentRoundTripper
func (rt *userAgentRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if _, ok := req.Header["User-Agent"]; !ok {
		req.Header.Set("User-Agent", rt.userAgent)
	}

	return rt.innerRt.RoundTrip(req)
}
