package http

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/efficientgo/core/testutil"

	"github.com/observatorium/api/authentication"
	"github.com/observatorium/api/authorization"
)

func TestDetectAdminQuery(t *testing.T) {
	tt := []struct {
		desc        string
		fieldName   string
		subject     string
		queryString string
		expectAdmin bool
		expectError bool
	}{
		{
			desc:        "query without user field",
			fieldName:   "user_id",
			subject:     "john.doe@example.com",
			queryString: `{namespace="prod"}`,
			expectAdmin: true,
			expectError: false,
		},
		{
			desc:        "query with user field matching subject",
			fieldName:   "user_id",
			subject:     "john.doe@example.com",
			queryString: `{namespace="prod"} | user_id = "john.doe@example.com"`,
			expectAdmin: false,
			expectError: false,
		},
		{
			desc:        "query with user field NOT matching subject",
			fieldName:   "user_id",
			subject:     "john.doe@example.com",
			queryString: `{namespace="prod"} | user_id = "jane.smith@example.com"`,
			expectAdmin: true,
			expectError: false,
		},
		{
			desc:        "query with empty user field value",
			fieldName:   "user_id",
			subject:     "john.doe@example.com",
			queryString: `{namespace="prod"} | user_id = ""`,
			expectAdmin: true,
			expectError: false,
		},
		{
			desc:        "query with user field and other filters",
			fieldName:   "user_id",
			subject:     "admin@example.com",
			queryString: `{namespace="prod"} | user_id = "admin@example.com" | json | level = "error"`,
			expectAdmin: false,
			expectError: false,
		},
		{
			desc:        "custom field name",
			fieldName:   "subject",
			subject:     "user123",
			queryString: `{namespace="prod"} | subject = "user123"`,
			expectAdmin: false,
			expectError: false,
		},
		{
			desc:        "custom field name with mismatch",
			fieldName:   "subject",
			subject:     "user123",
			queryString: `{namespace="prod"} | subject = "user456"`,
			expectAdmin: true,
			expectError: false,
		},
		{
			desc:        "invalid LogQL query",
			fieldName:   "user_id",
			subject:     "john.doe@example.com",
			queryString: `{this is not valid logql`,
			expectAdmin: true,
			expectError: true,
		},
		{
			desc:        "metric expression without log query",
			fieldName:   "user_id",
			subject:     "john.doe@example.com",
			queryString: `100 * 100`,
			expectAdmin: true,
			expectError: false,
		},
		{
			desc:        "query with multiple pipeline stages",
			fieldName:   "user_id",
			subject:     "test@example.com",
			queryString: `{app="myapp"} | json | line_format "{{.msg}}" | user_id = "test@example.com"`,
			expectAdmin: false,
			expectError: false,
		},
	}

	for _, tc := range tt {
		t.Run(tc.desc, func(t *testing.T) {
			isAdmin, err := detectAdminQuery(tc.fieldName, tc.subject, tc.queryString)

			if tc.expectError {
				testutil.Assert(t, err != nil, "expected error but got none")
			} else {
				testutil.Ok(t, err)
			}

			testutil.Equals(t, tc.expectAdmin, isAdmin,
				"expected isAdmin=%v, got isAdmin=%v", tc.expectAdmin, isAdmin)
		})
	}
}

func TestWithAdminQueryDetectorMiddleware(t *testing.T) {
	tt := []struct {
		desc              string
		fieldName         string
		subject           string
		urlPath           string
		queryParam        string
		expectAdminFlag   bool
		expectFlagPresent bool
	}{
		{
			desc:              "query without user field - should set admin flag",
			fieldName:         "user_id",
			subject:           "john.doe@example.com",
			urlPath:           "/loki/api/v1/query",
			queryParam:        `{namespace="prod"}`,
			expectAdminFlag:   true,
			expectFlagPresent: true,
		},
		{
			desc:              "query with matching user field - should not set admin flag",
			fieldName:         "user_id",
			subject:           "john.doe@example.com",
			urlPath:           "/loki/api/v1/query",
			queryParam:        `{namespace="prod"} | user_id = "john.doe@example.com"`,
			expectAdminFlag:   false,
			expectFlagPresent: true,
		},
		{
			desc:              "query with different user field - should set admin flag",
			fieldName:         "user_id",
			subject:           "john.doe@example.com",
			urlPath:           "/loki/api/v1/query",
			queryParam:        `{namespace="prod"} | user_id = "jane.smith@example.com"`,
			expectAdminFlag:   true,
			expectFlagPresent: true,
		},
		{
			desc:              "series endpoint - should skip detection",
			fieldName:         "user_id",
			subject:           "john.doe@example.com",
			urlPath:           "/loki/api/v1/series",
			queryParam:        `{namespace="prod"}`,
			expectAdminFlag:   false,
			expectFlagPresent: false,
		},
		{
			desc:              "empty query parameter - should skip detection",
			fieldName:         "user_id",
			subject:           "john.doe@example.com",
			urlPath:           "/loki/api/v1/labels",
			queryParam:        "",
			expectAdminFlag:   false,
			expectFlagPresent: false,
		},
		{
			desc:              "query_range endpoint with admin query",
			fieldName:         "user_id",
			subject:           "admin@example.com",
			urlPath:           "/loki/api/v1/query_range",
			queryParam:        `{app="test"}`,
			expectAdminFlag:   true,
			expectFlagPresent: true,
		},
		{
			desc:              "values endpoint with user query",
			fieldName:         "user_id",
			subject:           "user@example.com",
			urlPath:           "/loki/api/v1/label/namespace/values",
			queryParam:        `{namespace="prod"} | user_id = "user@example.com"`,
			expectAdminFlag:   false,
			expectFlagPresent: true,
		},
	}

	for _, tc := range tt {
		t.Run(tc.desc, func(t *testing.T) {
			var capturedAdminFlag bool
			var capturedFlagPresent bool

			// Create a next handler that captures the admin flag from context
			nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				capturedAdminFlag, capturedFlagPresent = authorization.GetIsAdminQuery(r.Context())
				w.WriteHeader(http.StatusOK)
			})

			// Create the middleware
			middleware := WithAdminQueryDetector(tc.fieldName)
			handler := middleware(nextHandler)

			// Create request URL with query parameter
			reqURL := tc.urlPath
			if tc.queryParam != "" {
				reqURL += "?query=" + url.QueryEscape(tc.queryParam)
			}
			req := httptest.NewRequest("GET", reqURL, nil)

			// Add subject to context
			ctx := authentication.WithSubjectForTesting(req.Context(), tc.subject)
			req = req.WithContext(ctx)

			// Execute the handler
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			// Verify the flag was set correctly
			testutil.Equals(t, tc.expectFlagPresent, capturedFlagPresent,
				"expected flag present=%v, got flag present=%v", tc.expectFlagPresent, capturedFlagPresent)

			if tc.expectFlagPresent {
				testutil.Equals(t, tc.expectAdminFlag, capturedAdminFlag,
					"expected admin flag=%v, got admin flag=%v", tc.expectAdminFlag, capturedAdminFlag)
			}
		})
	}
}

func TestWithAdminQueryDetectorMiddleware_NoSubject(t *testing.T) {
	// Test that middleware doesn't set flag when subject is missing
	var capturedFlagPresent bool

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, capturedFlagPresent = authorization.GetIsAdminQuery(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	middleware := WithAdminQueryDetector("user_id")
	handler := middleware(nextHandler)

	reqURL := "/loki/api/v1/query?query=" + url.QueryEscape(`{namespace="prod"}`)
	req := httptest.NewRequest("GET", reqURL, nil)
	// Don't add subject to context

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.Equals(t, false, capturedFlagPresent,
		"expected no flag when subject is missing")
}
