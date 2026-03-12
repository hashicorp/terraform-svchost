// Copyright (c) HashiCorp, Inc.

package auth

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"

	"github.com/zclconf/go-cty/cty"
)

// HostCredentialsMTLS is a HostCredentials implementation that represents
// mTLS (Mutual TLS) credentials, using client certificates and keys.
// It can also include a bearer token for application-level authorization.
type HostCredentialsMTLS struct {
	ClientCert    string
	ClientKey     string
	CACertificate string
	TokenValue    string
}

// Ensure HostCredentialsMTLS implements HostCredentialsExtended
var _ HostCredentialsExtended = &HostCredentialsMTLS{}

// PrepareRequest prepares the HTTP request by setting the Authorization
// header and configuring mTLS if available.
func (c *HostCredentialsMTLS) PrepareRequest(req *http.Request) {
	if req.Header == nil {
		req.Header = http.Header{}
	}

	// Set the Authorization header if a token is present
	if c.TokenValue != "" {
		req.Header.Set("Authorization", "Bearer "+c.TokenValue)
	}

	// Note: The actual mTLS setup usually happens at the transport layer,
	// which is outside the scope of this PrepareRequest method.
}

// GetTLSConfig returns a TLS configuration for mTLS authentication.
func (c *HostCredentialsMTLS) GetTLSConfig() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(c.ClientCert, c.ClientKey)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	if c.CACertificate != "" {
		caCert, err := os.ReadFile(c.CACertificate)
		if err != nil {
			return nil, err
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, err
		}

		tlsConfig.RootCAs = caCertPool
	}

	return tlsConfig, nil
}

// Token returns the bearer token associated with the credentials.
func (c *HostCredentialsMTLS) Token() string {
	return c.TokenValue
}

// SetToken sets the token value for the credentials.
func (c *HostCredentialsMTLS) SetToken(token string) {
	c.TokenValue = token
}

// ToStore serializes the mTLS credentials and token for storage.
func (c *HostCredentialsMTLS) ToStore() cty.Value {
	return cty.ObjectVal(map[string]cty.Value{
		"client_cert": cty.StringVal(c.ClientCert),
		"client_key":  cty.StringVal(c.ClientKey),
		"ca_cert":     cty.StringVal(c.CACertificate),
		"token":       cty.StringVal(c.TokenValue),
	})
}
