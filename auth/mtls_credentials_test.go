package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/zclconf/go-cty/cty"
)

func generateSelfSignedCert() (certFile, keyFile string, err error) {
	// Generate a private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}

	// Create a self-signed certificate
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Organization"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return "", "", err
	}

	// Encode the certificate and key to PEM format
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return "", "", err
	}
	keyPEMBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyPEM})

	// Write the certificate and key to temporary files
	certTempFile, err := os.CreateTemp("", "cert.pem")
	if err != nil {
		return "", "", err
	}
	defer certTempFile.Close()
	if _, err := certTempFile.Write(certPEM); err != nil {
		return "", "", err
	}

	keyTempFile, err := os.CreateTemp("", "key.pem")
	if err != nil {
		return "", "", err
	}
	defer keyTempFile.Close()
	if _, err := keyTempFile.Write(keyPEMBytes); err != nil {
		return "", "", err
	}

	return certTempFile.Name(), keyTempFile.Name(), nil
}

func TestHostCredentialsMTLS(t *testing.T) {
	// Generate self-signed cert and key
	certFile, keyFile, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("failed to generate self-signed cert: %v", err)
	}
	defer os.Remove(certFile)
	defer os.Remove(keyFile)

	creds := &HostCredentialsMTLS{
		ClientCert:    certFile,
		ClientKey:     keyFile,
		CACertificate: "", // optional CA
		TokenValue:    "foo-bar",
	}

	// Test PrepareRequest
	t.Run("PrepareRequest", func(t *testing.T) {
		req := &http.Request{Header: make(http.Header)}
		creds.PrepareRequest(req)
		authStr := req.Header.Get("Authorization")
		if got, want := authStr, "Bearer foo-bar"; got != want {
			t.Errorf("wrong Authorization header value %q; want %q", got, want)
		}
	})

	// Test GetTLSConfig
	t.Run("GetTLSConfig", func(t *testing.T) {
		tlsConfig, err := creds.GetTLSConfig()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Check if tlsConfig is nil, which would indicate a problem
		if tlsConfig == nil {
			t.Fatalf("tlsConfig is nil; expected a valid TLS configuration")
		}

		if len(tlsConfig.Certificates) != 1 {
			t.Errorf("expected 1 certificate, got %d", len(tlsConfig.Certificates))
		}

		// Further checks can be added to validate the loaded certificates,
		// but those would typically require actual files and might be more
		// suitable for integration tests.
	})

	// Test ToStore
	t.Run("ToStore", func(t *testing.T) {
		got := creds.ToStore()
		want := cty.ObjectVal(map[string]cty.Value{
			"client_cert": cty.StringVal(certFile),
			"client_key":  cty.StringVal(keyFile),
			"ca_cert":     cty.StringVal(""),
			"token":       cty.StringVal("foo-bar"),
		})
		if !want.RawEquals(got) {
			t.Errorf("wrong storable object value\ngot:  %#v\nwant: %#v", got, want)
		}
	})
}
