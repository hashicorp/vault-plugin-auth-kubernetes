// Copyright IBM Corp. 2017, 2026
// SPDX-License-Identifier: MPL-2.0

package kubeauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTokenReviewAPI_HTTP401IsReviewerRejection(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"kind":"Status","apiVersion":"v1","status":"Failure","message":"Unauthorized","code":401}`))
	}))
	t.Cleanup(srv.Close)

	tr := &tokenReviewAPI{config: &kubeConfig{Host: srv.URL}}
	_, err := tr.Review(context.Background(), srv.Client(), "fake.jwt.token", nil)
	if !errors.Is(err, errTokenReviewUnauthorized) {
		t.Fatalf("expected errTokenReviewUnauthorized, got %v", err)
	}
	if !isTokenReviewMisconfiguration(err) {
		t.Fatal("HTTP 401 from TokenReview must be classified as a misconfiguration")
	}
	if strings.Contains(err.Error(), "deleted") {
		t.Fatalf("HTTP 401 must not be described as a deleted service account: %v", err)
	}
}

func TestTokenReviewAPI_HTTP403IsReviewerRejection(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"kind":"Status","apiVersion":"v1","status":"Failure","message":"Forbidden","code":403}`))
	}))
	t.Cleanup(srv.Close)

	tr := &tokenReviewAPI{config: &kubeConfig{Host: srv.URL}}
	_, err := tr.Review(context.Background(), srv.Client(), "fake.jwt.token", nil)
	if !errors.Is(err, errTokenReviewForbidden) {
		t.Fatalf("expected errTokenReviewForbidden, got %v", err)
	}
	if !isTokenReviewMisconfiguration(err) {
		t.Fatal("HTTP 403 from TokenReview must be classified as a misconfiguration")
	}
}

func TestTokenReviewAPI_UnauthenticatedJWTIsNotMisconfiguration(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview","status":{"authenticated":false}}`))
	}))
	t.Cleanup(srv.Close)

	tr := &tokenReviewAPI{config: &kubeConfig{Host: srv.URL}}
	_, err := tr.Review(context.Background(), srv.Client(), "fake.jwt.token", nil)
	if err == nil {
		t.Fatal("expected error for unauthenticated token")
	}
	if isTokenReviewMisconfiguration(err) {
		t.Fatalf("authenticated=false is a login rejection, not a misconfiguration: %v", err)
	}
	if err.Error() != "lookup failed: service account jwt not valid" {
		t.Fatalf("unexpected error: %v", err)
	}
}
