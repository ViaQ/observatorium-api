package authentication

import "context"

// WithSubjectForTesting adds a subject to the context for testing purposes only.
// This should only be used in tests outside the authentication package that need to
// simulate an authenticated request (e.g., testing middleware that depends on GetSubject).
//
// Note: This function exists because subjectKey is intentionally private to prevent
// direct manipulation in production code. In real scenarios, subjects are set by
// authentication middleware (OIDC, mTLS, OpenShift, etc.).
func WithSubjectForTesting(ctx context.Context, subject string) context.Context {
	return context.WithValue(ctx, subjectKey, subject)
}
