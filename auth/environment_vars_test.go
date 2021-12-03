package auth

import (
	"testing"

	svchost "github.com/hashicorp/terraform-svchost"
)

func TestEnvVarsCredentialsSource(t *testing.T) {
	environ := []string{
		"TF_TOKEN_boop=single_label", // we allow single label here, though other contexts can disallow it
		"TF_TOKEN_tf_example_com=underscores",
		"TF_TOKEN_tf.example.net=dots", // we accept this if we're running in a context where it's possible
		"TF_TOKEN_Испытание_com=cyrillic_case_fold",
		"TF_TOKEN_example.com:8443=port_number", // we accept this if we're running in a context where it's possible
		"TF_TOKEN_overridden_example_com=not_overridden",
		"TF_TOKEN_overridden_example_com=overridden",

		// NOTE: This is the punycode encoding of boop.испытание.com
		"TF_TOKEN_boop_xn--80akhbyknj4f_com=punycode",

		// NOTE: This one contains a u followed by a combining diaeresis,
		// which should be normalized into a precomposed ü by the nameprep
		// algorithm, allowing us to look it up by is canonical punycode
		// form below.
		"TF_TOKEN_mu\u0308nchen.de=nameprep_normalization",

		"HOME=/home/example",          // should be silently ignored: irrelevant
		"TF_TOKEN=invalid",            // should be silently ignored: invalid prefix
		"TF_TOKEN_=invalid",           // should be silently ignored: empty hostname portion
		"TF_TOKEN_%=invalid",          // should be silently ignored: invalid hostname portion
		"TF_TOKEN_blah__blah=invalid", // should be silently ignored: invalid hostname portion
		"TF_TOKEN_beep..beep=invalid", // should be silently ignored: invalid hostname portion
	}

	creds := EnvVarsCredentialsSource(environ)

	tests := []struct {
		// NOTE: values of svchost.Hostname are always expected to be in
		// "ForComparison" (punicode) form, so it doesn't make sense to test
		// inputs that aren't in that form here, even though we can technically
		// construct such values here by bypassing svchost.ForComparison's
		// validation rules.
		hostname  svchost.Hostname
		wantToken string
	}{
		{
			svchost.Hostname("unknown.example.org"),
			"",
		},
		{
			svchost.Hostname("boop"),
			"single_label",
		},
		{
			svchost.Hostname("tf.example.com"),
			"underscores",
		},
		{
			svchost.Hostname("tf.example.net"),
			"dots",
		},
		{
			svchost.Hostname("xn--80akhbyknj4f.com"), // испытание.com
			"cyrillic_case_fold",
		},
		{
			svchost.Hostname("example.com:8443"),
			"port_number",
		},
		{
			svchost.Hostname("overridden.example.com"),
			"overridden", // later definition in the list "wins"
		},
		{
			svchost.Hostname("boop.xn--80akhbyknj4f.com"), // boop.испытание.com
			"punycode", // later definition in the list "wins"
		},
		{
			svchost.Hostname("xn--mnchen-3ya.de"), // münchen.de
			"nameprep_normalization",
		},
	}

	for _, test := range tests {
		t.Run(test.hostname.String(), func(t *testing.T) {
			got, err := creds.ForHost(test.hostname)
			if err != nil {
				t.Fatal(err) // should never happen for this source
			}

			if test.wantToken == "" {
				if got != nil {
					t.Errorf("wrong token\ngot:  %s\nwant: <nil>", got.Token())
				}
				return
			}

			if got == nil {
				t.Errorf("wrong token\ngot:  <nil>\nwant: %s", test.wantToken)
				return
			}

			gotToken := got.Token()
			if gotToken != test.wantToken {
				t.Errorf("wrong token\ngot:  %s\nwant: %s", gotToken, test.wantToken)
			}
		})
	}
}
