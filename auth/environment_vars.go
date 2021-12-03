package auth

import (
	"strings"

	svchost "github.com/hashicorp/terraform-svchost"
)

// EnvVarsCredentialsSource returns a credentials source that derives
// credentials from a set of environment variable values, given in the
// structure returned by the Go standard library function os.Environ.
//
// Currently this function supports environment variables whose names
// have the prefix TF_TOKEN_, followed by a string that can be converted
// to a valid service hostname by the following process:
//   - Replace any U+005F (underscore) with U+002E (period), to work
//     better in contexts that require shell-identifier-like environment
//     variable names.
//   - Process the result using svchost.ForDisplay, to normalize it.
//   - Parse the result using svchost.ForComparison, to obtain a value
//     suitable for handling hostname lookups.
//
// For any environment variable accepted by the above, the resulting
// credentials source will return a HostCredentials object which includes
// the "token" argument set to the environment variable value, verbatim.
// Any variable names without that prefix or whose suffix isn't
// valid per the processing steps that follow will be silently ignored.
//
// Note that this credentials strategy doesn't easily support hostnames which
// include non-standard port numbers, unless the caller sets environment
// variables through a mechanism that will allow a colon in the environment
// variable name. Non-standard port numbers are part of the svchost syntax only
// as an aid to service development and not intended for production use; use
// other credential sources to provide credentials for hostnames containing
// port numbers.
//
// If multiple environment variable names normalize to the same hostname
// under the rules above, the last one in the environ sequence will take
// priority.
//
// Future versions of this function may support additional environment
// variable name prefixes, possibly generating HostCredentials objects
// with different property names.
func EnvVarsCredentialsSource(environ []string) CredentialsSource {

	// As an implementation detail this is actually implemented in terms
	// of StaticCredentialsSource, so we'll construct a map to pass
	// into that function here.
	var creds map[svchost.Hostname]map[string]interface{}

	for _, ev := range environ {
		eqIdx := strings.Index(ev, "=")
		if eqIdx < 0 {
			continue
		}
		name := ev[:eqIdx]
		value := ev[eqIdx+1:]

		hostname, valid := CredentialsHostnameForEnvVar(name)
		if !valid {
			continue
		}

		if creds == nil {
			creds = make(map[svchost.Hostname]map[string]interface{})
		}
		creds[hostname] = map[string]interface{}{
			"token": value,
		}
	}

	return StaticCredentialsSource(creds)
}

// CredentialsHostnameForEnvVar returns the hostname that the given environment
// variable name would serve to declare credentials for if passed to
// EnvVarCredentialsSource, if any.
//
// If the second return value is false, the given name doesn't meet any of
// the expected naming schemes handled by CredentialsHostnameForEnvVar.
//
// This is here primarily to help give feedback about specific environment
// variable names in error messages. EnvVarsCredentialsSource is the main
// way to process environment-based credentials in normal codepaths.
func CredentialsHostnameForEnvVar(name string) (svchost.Hostname, bool) {
	const prefix = "TF_TOKEN_"

	if !strings.HasPrefix(name, prefix) {
		return "", false
	}
	rawHost := name[len(prefix):]
	// We accept underscores in place of dots because dots are not valid
	// identifiers in most shells and are therefore hard to set.
	// Underscores are not valid in hostnames, so this is unambiguous for
	// valid hostnames.
	rawHost = strings.ReplaceAll(rawHost, "_", ".")

	// Because environment variables are often set indirectly by OS
	// libraries that might interfere with how they are encoded, we'll
	// be tolerant of them being given either directly as UTF-8 IDNs
	// or in Punycode form, normalizing to Punycode form here because
	// that is what the Terraform credentials helper protocol will
	// use in its requests.
	//
	// Using ForDisplay first here makes this more liberal than Terraform
	// itself would usually be in that it will tolerate pre-punycoded
	// hostnames that Terraform normally rejects in other contexts in order
	// to ensure stored hostnames are human-readable.
	dispHost := svchost.ForDisplay(rawHost)
	hostname, err := svchost.ForComparison(dispHost)
	if err != nil {
		// Ignore invalid hostnames
		return "", false
	}

	return hostname, true
}
