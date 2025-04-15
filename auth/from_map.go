// Copyright (c) HashiCorp, Inc.

package auth

import (
	"github.com/zclconf/go-cty/cty"
)

// HostCredentialsFromMap converts a map of key-value pairs from a credentials
// definition provided by the user (e.g. in a config file, or via a credentials
// helper) into a HostCredentials object if possible, or returns nil if
// no credentials could be extracted from the map.
//
// This function ignores map keys it is unfamiliar with, to allow for future
// expansion of the credentials map format for new credential types.
func HostCredentialsFromMap(m map[string]interface{}) HostCredentials {
	if m == nil {
		return nil
	}

	// Check for mTLS credentials
	clientCert, certOk := m["client_cert"].(string)
	clientKey, keyOk := m["client_key"].(string)
	caCert, _ := m["ca_cert"].(string) // CA cert is optional

	if certOk && keyOk {
		token, _ := m["token"].(string) // token is optional
		return &HostCredentialsMTLS{
			ClientCert:    clientCert,
			ClientKey:     clientKey,
			CACertificate: caCert,
			TokenValue:    token,
		}
	}

	// If no mTLS, check for token only
	if token, ok := m["token"].(string); ok {
		return HostCredentialsToken(token)
	}

	return nil
}

// HostCredentialsFromObject converts a cty.Value of an object type into a
// HostCredentials object if possible, or returns nil if no credentials could
// be extracted from the map.
//
// This function ignores object attributes it is unfamiliar with, to allow for
// future expansion of the credentials object structure for new credential types.
//
// If the given value is not of an object type, this function will panic.
func HostCredentialsFromObject(obj cty.Value) HostCredentials {
	if obj.IsNull() || !obj.IsKnown() {
		return nil
	}

	// Check for mTLS credentials
	mtlsConfig := mTLSCredentialsFromObject(obj)
	if mtlsConfig != nil {
		token := ""
		if obj.Type().HasAttribute("token") {
			tokenV := obj.GetAttr("token")
			if !tokenV.IsNull() && tokenV.IsKnown() && cty.String.Equals(tokenV.Type()) {
				token = tokenV.AsString()
			}
		}
		return &HostCredentialsMTLS{
			ClientCert:    mtlsConfig.ClientCert,
			ClientKey:     mtlsConfig.ClientKey,
			CACertificate: mtlsConfig.CACertificate,
			TokenValue:    token,
		}
	}

	// Check for token only
	if obj.Type().HasAttribute("token") {
		tokenV := obj.GetAttr("token")
		if !tokenV.IsNull() && tokenV.IsKnown() && cty.String.Equals(tokenV.Type()) {
			return HostCredentialsToken(tokenV.AsString())
		}
	}

	return nil
}

func mTLSCredentialsFromObject(obj cty.Value) *HostCredentialsMTLS {
	if obj.IsNull() || !obj.IsKnown() || !obj.CanIterateElements() {
		return nil
	}

	var cert, key, caCert string

	if certAttr := obj.GetAttr("client_cert"); certAttr.IsKnown() && !certAttr.IsNull() {
		cert = certAttr.AsString()
	}
	if keyAttr := obj.GetAttr("client_key"); keyAttr.IsKnown() && !keyAttr.IsNull() {
		key = keyAttr.AsString()
	}
	if caAttr := obj.GetAttr("ca_cert"); caAttr.IsKnown() && !caAttr.IsNull() {
		caCert = caAttr.AsString()
	}

	if cert != "" && key != "" {
		return &HostCredentialsMTLS{
			ClientCert:    cert,
			ClientKey:     key,
			CACertificate: caCert,
		}
	}

	return nil
}
