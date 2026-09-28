// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package verify

import "testing"

// FuzzBadgeParsers checks that untrusted badge JSON cannot crash any accepted format parser.
func FuzzBadgeParsers(f *testing.F) {
	f.Add([]byte(`{"vcs":[{"envelopeType":"CREDENTIAL_ENVELOPE_TYPE_JOSE","value":"example"}]}`))
	f.Add([]byte(`{"vcs":[null]}`))
	f.Add([]byte(`{"vcs":[{}]}`))
	f.Add([]byte(`[null]`))
	f.Add([]byte(`{"envelopeType":"CREDENTIAL_ENVELOPE_TYPE_JOSE","value":"example"}`))
	f.Add([]byte(`not json`))

	f.Fuzz(func(t *testing.T, data []byte) {
		for _, parser := range fileParsers {
			credentials, err := parser(data)
			if err != nil {
				continue
			}

			for _, credential := range credentials {
				if credential == nil {
					t.Fatal("parser returned a nil credential without an error")
				}
			}
		}
	})
}
