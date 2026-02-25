// Copyright IBM Corp. 2017, 2026

package disco

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	svchost "github.com/hashicorp/terraform-svchost"
	"github.com/hashicorp/terraform-svchost/auth"
)

func TestMain(m *testing.M) {
	// During all tests we override the HTTP transport we use for discovery
	// so it'll tolerate the locally-generated TLS certificates we use
	// for test URLs.
	httpTransport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	// Use minimal retry wait times so tests don't wait for production
	// back-off intervals.
	retryWaitMin = 1 * time.Millisecond
	retryWaitMax = 10 * time.Millisecond

	os.Exit(m.Run())
}

func TestDiscover(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		portStr, cleanup := testServer(func(w http.ResponseWriter, r *http.Request) {
			resp := []byte(`
{
"thingy.v1": "http://example.com/foo",
"wotsit.v2": "http://example.net/bar"
}
`)
			w.Header().Add("Content-Type", "application/json")
			w.Header().Add("Content-Length", strconv.Itoa(len(resp)))
			w.Write(resp)
		})
		defer cleanup()

		givenHost := "localhost" + portStr
		host, err := svchost.ForComparison(givenHost)
		if err != nil {
			t.Fatalf("test server hostname is invalid: %s", err)
		}

		d := New()
		discovered, err := d.Discover(host)
		if err != nil {
			t.Fatalf("unexpected discovery error: %s", err)
		}

		gotURL, err := discovered.ServiceURL("thingy.v1")
		if err != nil {
			t.Fatalf("unexpected service URL error: %s", err)
		}
		if gotURL == nil {
			t.Fatalf("found no URL for thingy.v1")
		}
		if got, want := gotURL.String(), "http://example.com/foo"; got != want {
			t.Fatalf("wrong result %q; want %q", got, want)
		}
	})
	t.Run("chunked encoding", func(t *testing.T) {
		portStr, cleanup := testServer(func(w http.ResponseWriter, r *http.Request) {
			resp := []byte(`
{
"thingy.v1": "http://example.com/foo",
"wotsit.v2": "http://example.net/bar"
}
`)
			w.Header().Add("Content-Type", "application/json")
			// We're going to force chunked encoding here -- and thus prevent
			// the server from predicting the length -- so we can make sure
			// our client is tolerant of servers using this encoding.
			w.Write(resp[:5])
			w.(http.Flusher).Flush()
			w.Write(resp[5:])
			w.(http.Flusher).Flush()
		})
		defer cleanup()

		givenHost := "localhost" + portStr
		host, err := svchost.ForComparison(givenHost)
		if err != nil {
			t.Fatalf("test server hostname is invalid: %s", err)
		}

		d := New()
		discovered, err := d.Discover(host)
		if err != nil {
			t.Fatalf("unexpected discovery error: %s", err)
		}

		gotURL, err := discovered.ServiceURL("wotsit.v2")
		if err != nil {
			t.Fatalf("unexpected service URL error: %s", err)
		}
		if gotURL == nil {
			t.Fatalf("found no URL for wotsit.v2")
		}
		if got, want := gotURL.String(), "http://example.net/bar"; got != want {
			t.Fatalf("wrong result %q; want %q", got, want)
		}
	})
	t.Run("with credentials", func(t *testing.T) {
		var authHeaderText string
		portStr, cleanup := testServer(func(w http.ResponseWriter, r *http.Request) {
			resp := []byte(`{}`)
			authHeaderText = r.Header.Get("Authorization")
			w.Header().Add("Content-Type", "application/json")
			w.Header().Add("Content-Length", strconv.Itoa(len(resp)))
			w.Write(resp)
		})
		defer cleanup()

		givenHost := "localhost" + portStr
		host, err := svchost.ForComparison(givenHost)
		if err != nil {
			t.Fatalf("test server hostname is invalid: %s", err)
		}

		d := New()
		d.SetCredentialsSource(auth.StaticCredentialsSource(map[svchost.Hostname]map[string]interface{}{
			host: {
				"token": "abc123",
			},
		}))
		d.Discover(host)
		if got, want := authHeaderText, "Bearer abc123"; got != want {
			t.Fatalf("wrong Authorization header\ngot:  %s\nwant: %s", got, want)
		}
	})
	t.Run("forced services override", func(t *testing.T) {
		forced := map[string]interface{}{
			"thingy.v1": "http://example.net/foo",
			"wotsit.v2": "/foo",
		}

		d := New()
		d.ForceHostServices(svchost.Hostname("example.com"), forced)

		givenHost := "example.com"
		host, err := svchost.ForComparison(givenHost)
		if err != nil {
			t.Fatalf("test server hostname is invalid: %s", err)
		}

		discovered, err := d.Discover(host)
		if err != nil {
			t.Fatalf("unexpected discovery error: %s", err)
		}
		{
			gotURL, err := discovered.ServiceURL("thingy.v1")
			if err != nil {
				t.Fatalf("unexpected service URL error: %s", err)
			}
			if gotURL == nil {
				t.Fatalf("found no URL for thingy.v1")
			}
			if got, want := gotURL.String(), "http://example.net/foo"; got != want {
				t.Fatalf("wrong result %q; want %q", got, want)
			}
		}
		{
			gotURL, err := discovered.ServiceURL("wotsit.v2")
			if err != nil {
				t.Fatalf("unexpected service URL error: %s", err)
			}
			if gotURL == nil {
				t.Fatalf("found no URL for wotsit.v2")
			}
			if got, want := gotURL.String(), "https://example.com/foo"; got != want {
				t.Fatalf("wrong result %q; want %q", got, want)
			}
		}
	})
	t.Run("not JSON", func(t *testing.T) {
		portStr, cleanup := testServer(func(w http.ResponseWriter, r *http.Request) {
			resp := []byte(`{"thingy.v1": "http://example.com/foo"}`)
			w.Header().Add("Content-Type", "application/octet-stream")
			w.Write(resp)
		})
		defer cleanup()

		givenHost := "localhost" + portStr
		host, err := svchost.ForComparison(givenHost)
		if err != nil {
			t.Fatalf("test server hostname is invalid: %s", err)
		}

		d := New()
		discovered, err := d.Discover(host)
		if err == nil {
			t.Fatalf("expected a discovery error")
		}

		// Returned discovered should be nil.
		if discovered != nil {
			t.Errorf("discovered not nil; should be")
		}
	})
	t.Run("malformed JSON", func(t *testing.T) {
		portStr, cleanup := testServer(func(w http.ResponseWriter, r *http.Request) {
			resp := []byte(`{"thingy.v1": "htt`) // truncated, for example...
			w.Header().Add("Content-Type", "application/json")
			w.Write(resp)
		})
		defer cleanup()

		givenHost := "localhost" + portStr
		host, err := svchost.ForComparison(givenHost)
		if err != nil {
			t.Fatalf("test server hostname is invalid: %s", err)
		}

		d := New()
		discovered, err := d.Discover(host)
		if err == nil {
			t.Fatalf("expected a discovery error")
		}

		// Returned discovered should be nil.
		if discovered != nil {
			t.Errorf("discovered not nil; should be")
		}
	})
	t.Run("JSON with redundant charset", func(t *testing.T) {
		// The JSON RFC defines no parameters for the application/json
		// MIME type, but some servers have a weird tendency to just add
		// "charset" to everything, so we'll make sure we ignore it successfully.
		// (JSON uses content sniffing for encoding detection, not media type params.)
		portStr, cleanup := testServer(func(w http.ResponseWriter, r *http.Request) {
			resp := []byte(`{"thingy.v1": "http://example.com/foo"}`)
			w.Header().Add("Content-Type", "application/json; charset=latin-1")
			w.Write(resp)
		})
		defer cleanup()

		givenHost := "localhost" + portStr
		host, err := svchost.ForComparison(givenHost)
		if err != nil {
			t.Fatalf("test server hostname is invalid: %s", err)
		}

		d := New()
		discovered, err := d.Discover(host)
		if err != nil {
			t.Fatalf("unexpected discovery error: %s", err)
		}

		if discovered.services == nil {
			t.Errorf("response is empty; shouldn't be")
		}
	})
	t.Run("no discovery doc", func(t *testing.T) {
		portStr, cleanup := testServer(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(404)
		})
		defer cleanup()

		givenHost := "localhost" + portStr
		host, err := svchost.ForComparison(givenHost)
		if err != nil {
			t.Fatalf("test server hostname is invalid: %s", err)
		}

		d := New()
		discovered, err := d.Discover(host)

		if err != nil {
			t.Fatalf("unexpected discovery error: %s", err)
		}

		// Returned discovered.services should be nil (empty).
		if discovered.services != nil {
			t.Errorf("discovered.services not nil (empty); should be")
		}
	})
	t.Run("retries on 5xx", func(t *testing.T) {
		attemptCount := 0
		portStr, cleanup := testServer(func(w http.ResponseWriter, r *http.Request) {
			attemptCount++
			if attemptCount < 3 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			resp := []byte(`{"thingy.v1": "http://example.com/foo"}`)
			w.Header().Add("Content-Type", "application/json")
			w.Header().Add("Content-Length", strconv.Itoa(len(resp)))
			w.Write(resp)
		})
		defer cleanup()

		givenHost := "localhost" + portStr
		host, err := svchost.ForComparison(givenHost)
		if err != nil {
			t.Fatalf("test server hostname is invalid: %s", err)
		}

		d := New()
		discovered, err := d.Discover(host)
		if err != nil {
			t.Fatalf("expected success after retries, got: %s", err)
		}
		if discovered == nil {
			t.Fatalf("discovered should not be nil after successful retry")
		}
		if attemptCount != 3 {
			t.Errorf("expected 3 attempts, got %d", attemptCount)
		}

		gotURL, err := discovered.ServiceURL("thingy.v1")
		if err != nil {
			t.Fatalf("unexpected service URL error: %s", err)
		}
		if got, want := gotURL.String(), "http://example.com/foo"; got != want {
			t.Fatalf("wrong result %q; want %q", got, want)
		}
	})
	t.Run("retries on timeout", func(t *testing.T) {
		// Block only the first request so it times out, then succeed on retry.
		// Closing blockc after Discover returns lets the stalled handler
		// complete so the test server can shut down cleanly.
		blockc := make(chan struct{})
		var attemptCount atomic.Int32
		portStr, cleanup := testServer(func(w http.ResponseWriter, r *http.Request) {
			if attemptCount.Add(1) == 1 {
				<-blockc
				return
			}
			resp := []byte(`{"thingy.v1": "http://example.com/foo"}`)
			w.Header().Add("Content-Type", "application/json")
			w.Header().Add("Content-Length", strconv.Itoa(len(resp)))
			w.Write(resp)
		})
		defer cleanup()
		defer close(blockc)

		givenHost := "localhost" + portStr
		host, err := svchost.ForComparison(givenHost)
		if err != nil {
			t.Fatalf("test server hostname is invalid: %s", err)
		}

		d := New()
		transport := d.Transport.(*http.Transport)
		origTimeout := transport.ResponseHeaderTimeout
		transport.ResponseHeaderTimeout = 10 * time.Millisecond
		defer func() { transport.ResponseHeaderTimeout = origTimeout }()

		discovered, err := d.Discover(host)
		if err != nil {
			t.Fatalf("expected success after timeout retry, got: %s", err)
		}
		if discovered == nil {
			t.Fatalf("discovered should not be nil after successful retry")
		}
		if attemptCount.Load() < 2 {
			t.Errorf("expected at least 2 attempts (1 timeout + 1 success), got %d", attemptCount.Load())
		}

		gotURL, err := discovered.ServiceURL("thingy.v1")
		if err != nil {
			t.Fatalf("unexpected service URL error: %s", err)
		}
		if got, want := gotURL.String(), "http://example.com/foo"; got != want {
			t.Fatalf("wrong result %q; want %q", got, want)
		}
	})
	t.Run("discovery error", func(t *testing.T) {
		// Block every request to force a timeout on every attempt (including
		// retries). Closing the channel at the end unblocks all handlers so
		// the test server can shut down cleanly.
		donec := make(chan struct{})
		portStr, cleanup := testServer(func(w http.ResponseWriter, r *http.Request) {
			<-donec
		})
		defer cleanup()
		defer close(donec)

		givenHost := "localhost" + portStr
		host, err := svchost.ForComparison(givenHost)
		if err != nil {
			t.Fatalf("test server hostname is invalid: %s", err)
		}

		d := New()

		transport := d.Transport.(*http.Transport)

		origTimeout := transport.ResponseHeaderTimeout
		transport.ResponseHeaderTimeout = 10 * time.Millisecond
		defer func() { transport.ResponseHeaderTimeout = origTimeout }()
		discovered, err := d.Discover(host)

		// Verify the error is an ErrServiceDiscoveryNetworkRequest
		_, isDiscoError := err.(ErrServiceDiscoveryNetworkRequest)
		if !isDiscoError {
			t.Fatalf("was not an ErrServiceDiscoveryNetworkRequest, got %T %v", err, err)
		}

		// Returned discovered should be nil (empty).
		if discovered != nil {
			t.Errorf("discovered not nil (empty); should be")
		}
	})
	t.Run("redirect", func(t *testing.T) {
		// For this test, we have two servers and one redirects to the other
		portStr1, close1 := testServer(func(w http.ResponseWriter, r *http.Request) {
			// This server is the one that returns a real response.
			resp := []byte(`{"thingy.v1": "http://example.com/foo"}`)
			w.Header().Add("Content-Type", "application/json")
			w.Header().Add("Content-Length", strconv.Itoa(len(resp)))
			w.Write(resp)
		})
		portStr2, close2 := testServer(func(w http.ResponseWriter, r *http.Request) {
			// This server is the one that redirects.
			http.Redirect(w, r, "https://localhost"+portStr1+"/.well-known/terraform.json", http.StatusFound)
		})
		defer close1()
		defer close2()

		givenHost := "localhost" + portStr2
		host, err := svchost.ForComparison(givenHost)
		if err != nil {
			t.Fatalf("test server hostname is invalid: %s", err)
		}

		d := New()
		discovered, err := d.Discover(host)
		if err != nil {
			t.Fatalf("unexpected discovery error: %s", err)
		}

		gotURL, err := discovered.ServiceURL("thingy.v1")
		if err != nil {
			t.Fatalf("unexpected service URL error: %s", err)
		}
		if gotURL == nil {
			t.Fatalf("found no URL for thingy.v1")
		}
		if got, want := gotURL.String(), "http://example.com/foo"; got != want {
			t.Fatalf("wrong result %q; want %q", got, want)
		}

		// The base URL for the host object should be the URL we redirected to,
		// rather than the we redirected _from_.
		gotBaseURL := discovered.discoURL.String()
		wantBaseURL := "https://localhost" + portStr1 + "/.well-known/terraform.json"
		if gotBaseURL != wantBaseURL {
			t.Errorf("incorrect base url %s; want %s", gotBaseURL, wantBaseURL)
		}
	})

	t.Run("alias", func(t *testing.T) {
		// The server will listen on localhost and we will expect this response
		// by requesting discovery on the alias.
		portStr, cleanup := testServer(func(w http.ResponseWriter, r *http.Request) {
			resp := []byte(`
{
"thingy.v1": "http://example.com/foo"
}
`)
			w.Header().Add("Content-Type", "application/json")
			w.Header().Add("Content-Length", strconv.Itoa(len(resp)))
			w.Write(resp)
		})
		defer cleanup()

		target, err := svchost.ForComparison("localhost" + portStr)
		if err != nil {
			t.Fatalf("test server hostname is invalid: %s", err)
		}
		alias, err := svchost.ForComparison("not-a-real-host-dont-even-try.no")
		if err != nil {
			t.Fatalf("alias hostname is invalid: %s", err)
		}

		d := New()
		d.SetCredentialsSource(auth.StaticCredentialsSource(map[svchost.Hostname]map[string]any{
			target: {
				"token": "hunter2",
			},
		}))

		d.Alias(alias, target)

		discovered, err := d.Discover(alias)
		if err != nil {
			t.Fatalf("unexpected discovery error: %s", err)
		}

		gotURL, err := discovered.ServiceURL("thingy.v1")
		if err != nil {
			t.Fatalf("unexpected service URL error: %s", err)
		}
		if gotURL == nil {
			t.Fatalf("found no URL for thingy.v1")
		}
		if got, want := gotURL.String(), "http://example.com/foo"; got != want {
			t.Fatalf("wrong result %q; want %q", got, want)
		}

		aliasCreds, err := d.CredentialsForHost(alias)
		if err != nil {
			t.Fatalf("unexpected credentials error: %s", err)
		}
		if aliasCreds.Token() != "hunter2" {
			t.Fatalf("found no credentials for alias")
		}

		d.ForgetAlias(alias)

		discovered, err = d.Discover(alias)
		if err == nil {
			t.Error("expected error, got none")
		}
		if discovered != nil {
			t.Error("expected discovered to be nil, got non-nil")
		}
	})
}

func testServer(h func(w http.ResponseWriter, r *http.Request)) (portStr string, cleanup func()) {
	server := httptest.NewTLSServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			// Test server always returns 404 if the URL isn't what we expect
			if r.URL.Path != "/.well-known/terraform.json" {
				w.WriteHeader(404)
				w.Write([]byte("not found"))
				return
			}

			// If the URL is correct then the given hander decides the response
			h(w, r)
		},
	))

	serverURL, _ := url.Parse(server.URL)

	portStr = serverURL.Port()
	if portStr != "" {
		portStr = ":" + portStr
	}

	cleanup = func() {
		server.Close()
	}

	return portStr, cleanup
}
