// Copyright IBM Corp. 2017, 2025
// SPDX-License-Identifier: MPL-2.0

package kubeauth

import (
	"errors"
	"net"
	"net/http"
	"strings"

	kubeerrors "k8s.io/apimachinery/pkg/api/errors"
)

// isTokenReviewMisconfiguration reports whether a TokenReview failure is a
// reviewer-credential, transport, or API-server problem rather than a rejected
// login JWT. Those failures are logged at error; expected login denials stay
// at debug so unauthenticated clients cannot flood error logs. The HTTP
// response to the client remains permission denied in both cases.
func isTokenReviewMisconfiguration(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errTokenReviewUnauthorized) || errors.Is(err, errTokenReviewForbidden) {
		return true
	}

	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}

	var status kubeerrors.APIStatus
	if errors.As(err, &status) {
		code := status.Status().Code
		if code == http.StatusUnauthorized || code == http.StatusForbidden || code >= 500 {
			return true
		}
	}

	msg := err.Error()
	switch {
	case strings.Contains(msg, "x509:"),
		strings.Contains(msg, "tls:"),
		strings.Contains(msg, "no such host"),
		strings.Contains(msg, "connection refused"),
		strings.Contains(msg, "i/o timeout"),
		strings.Contains(msg, "context deadline exceeded"),
		strings.Contains(msg, "network is unreachable"):
		return true
	default:
		return false
	}
}

func setRequestHeader(req *http.Request, bearer string) {
	bearer = strings.TrimSpace(bearer)

	// Set the JWT as the Bearer token
	req.Header.Set("Authorization", bearer)

	// Set the MIME type headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
}
