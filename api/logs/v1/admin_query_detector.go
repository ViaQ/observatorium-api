package http

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/observatorium/api/authentication"
	"github.com/observatorium/api/authorization"
	logqlv2 "github.com/observatorium/api/logql/v2"
)

// WithAdminQueryDetector returns a middleware that detects if a query is an "admin query".
// An admin query is one that:
// - Does not contain the specified user field filter
// - Contains the user field filter with a value different from the authenticated subject (including empty)
//
// When an admin query is detected, a flag is stored in the request context that can be
// used by downstream middleware (like authorization) to modify the resource desired by subject sent to OPA.
func WithAdminQueryDetector(fieldName string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip detection for /series endpoint as it uses "match" parameter
			// which only supports stream labels, not structured metadata fields
			if strings.HasSuffix(r.URL.Path, "/series") {
				next.ServeHTTP(w, r)
				return
			}

			// No query parameter, treat as regular query (not admin)
			queryString := r.URL.Query().Get(queryParam)
			if queryString == "" {
				next.ServeHTTP(w, r)
				return
			}

			// No subject in context, can't determine admin status
			// Let the request continue without setting the flag
			subject, ok := authentication.GetSubject(r.Context())
			if !ok {
				next.ServeHTTP(w, r)
				return
			}

			isAdmin, _ := detectAdminQuery(fieldName, subject, queryString)
			// Note: We ignore the error from parsing. If parsing fails, detectAdminQuery
			// returns true (admin query) as a fail-safe approach.

			// Store the result in context
			ctx := authorization.WithIsAdminQuery(r.Context(), isAdmin)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// detectAdminQuery analyzes a LogQL query to determine if it's an admin query.
// Returns true if:
// - The user field is not present in the query
// - The user field value doesn't match the authenticated subject
// Returns false if the user field is present and matches the subject exactly.
func detectAdminQuery(fieldName, subject, queryString string) (bool, error) {
	// If parsing fails, treat as admin query (fail-safe)
	expr, err := logqlv2.ParseExpr(queryString)
	if err != nil {
		return true, err
	}

	// Walk the AST to find the user field
	var foundUserField bool
	var userFieldValue string

	expr.Walk(func(e interface{}) {
		if logQuery, ok := e.(*logqlv2.LogQueryExpr); ok {
			queryStr := logQuery.String()
			// Use regex to extract user field value
			// Pattern: | fieldName = "value"
			pattern := fmt.Sprintf(`\|\s*%s\s*=\s*"([^"]*)"`, regexp.QuoteMeta(fieldName))
			re := regexp.MustCompile(pattern)
			matches := re.FindStringSubmatch(queryStr)
			if len(matches) >= 2 {
				foundUserField = true
				userFieldValue = matches[1]
			}
		}
	})

	// No user field → admin query
	if !foundUserField {
		return true, nil
	}
	// Different user or empty value → admin quer
	if userFieldValue != subject {
		return true, nil
	}

	return false, nil // User querying their own logs → NOT admin query
}
