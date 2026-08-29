// Copyright IBM Corp. 2017, 2026
// SPDX-License-Identifier: MPL-2.0

package kubeauth

import (
	"errors"
	"fmt"
	"testing"
)

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestIsTokenReviewMisconfiguration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "unauthorized sentinel", err: errTokenReviewUnauthorized, want: true},
		{name: "forbidden sentinel", err: errTokenReviewForbidden, want: true},
		{name: "wrapped unauthorized", err: fmt.Errorf("lookup: %w", errTokenReviewUnauthorized), want: true},
		{name: "timeout", err: timeoutErr{}, want: true},
		{name: "tls string", err: errors.New(`Post "https://example:443/apis/authentication.k8s.io/v1/tokenreviews": tls: failed to verify certificate: x509: certificate signed by unknown authority`), want: true},
		{name: "dns string", err: errors.New("lookup failed: no such host"), want: true},
		{name: "deleted-looking login jwt", err: errors.New("lookup failed: service account jwt not valid"), want: false},
		{name: "jwt name mismatch", err: errors.New("JWT names did not match"), want: false},
		{name: "jwt uid mismatch", err: errors.New("JWT UIDs did not match"), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := isTokenReviewMisconfiguration(tt.err); got != tt.want {
				t.Fatalf("isTokenReviewMisconfiguration(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
