package main

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/go-chi/chi"
)

// setupTestEnforcer creates a test Casbin enforcer with the existing model and policy files
func setupTestEnforcer(t *testing.T) *casbin.Enforcer {
	e, err := casbin.NewEnforcer("authz_model.conf", "authz_policy_test.csv")
	if err != nil {
		t.Fatalf("Failed to create enforcer: %v", err)
	}
	
	if err = e.LoadPolicy(); err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}
	
	return e
}

// setupTestRouter creates a test router with all endpoints configured
func setupTestRouter(t *testing.T) *chi.Mux {
	router := chi.NewRouter()
	e := setupTestEnforcer(t)

	// Protected routes with authorization
	router.Group(func(r chi.Router) {
		r.Route("/api/v1", func(r chi.Router) {
			r.Use(Authorizer(e))
			r.Get("/data1", func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("bisa akses get endpoint data1"))
			})
			r.Post("/data1", func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("bisa akses post endpoint data1"))
			})
			r.Get("/data2", func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("bisa akses endpoint data2"))
			})
			r.Get("/", func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("bisa akses endpoint index/root"))
			})
		})
	})

	// Unprotected routes
	router.Get("/api/v2/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("GET api v2"))
	})

	router.Post("/api/v2/test", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("POST api v2"))
	})

	router.Post("/api/v2/updatepolicy", func(w http.ResponseWriter, r *http.Request) {
		res, err := e.AddPolicy("alice", "/api/v1/data1", "GET")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		
		fmt.Fprintf(w, "Policy added: %v", res)
		err = e.SavePolicy()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		
		w.Write([]byte(" - POST api update policy"))
	})

	return router
}

// createRequestWithAuth creates an HTTP request with basic authentication
func createRequestWithAuth(method, url, user, password string) *http.Request {
	req := httptest.NewRequest(method, url, nil)
	if user != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(user + ":" + password))
		req.Header.Set("Authorization", "Basic "+auth)
	}
	return req
}

// TestAuthorizer tests the authorization middleware functionality
func TestAuthorizer(t *testing.T) {
	e := setupTestEnforcer(t)
	
	tests := []struct {
		name           string
		user           string
		method         string
		path           string
		expectedStatus int
		description    string
	}{
		// Alice's permissions: GET /api/v1/, POST /api/v1/data1
		{
			name:           "Alice_GET_Root_Allowed",
			user:           "alice",
			method:         "GET",
			path:           "/api/v1/",
			expectedStatus: http.StatusOK,
			description:    "Alice should be able to GET /api/v1/",
		},
		{
			name:           "Alice_POST_Data1_Allowed",
			user:           "alice",
			method:         "POST",
			path:           "/api/v1/data1",
			expectedStatus: http.StatusOK,
			description:    "Alice should be able to POST /api/v1/data1",
		},
		{
			name:           "Alice_GET_Data1_Denied",
			user:           "alice",
			method:         "GET",
			path:           "/api/v1/data1",
			expectedStatus: http.StatusForbidden,
			description:    "Alice should NOT be able to GET /api/v1/data1",
		},
		{
			name:           "Alice_GET_Data2_Denied",
			user:           "alice",
			method:         "GET",
			path:           "/api/v1/data2",
			expectedStatus: http.StatusForbidden,
			description:    "Alice should NOT be able to GET /api/v1/data2",
		},
		
		// Bob's permissions: * /api/v1/resource1, GET /api/v1/resource2, POST /api/v1/*
		{
			name:           "Bob_GET_Resource1_Allowed",
			user:           "bob",
			method:         "GET",
			path:           "/api/v1/resource1",
			expectedStatus: http.StatusOK,
			description:    "Bob should be able to GET /api/v1/resource1 (wildcard access)",
		},
		{
			name:           "Bob_POST_Resource1_Allowed",
			user:           "bob",
			method:         "POST",
			path:           "/api/v1/resource1",
			expectedStatus: http.StatusOK,
			description:    "Bob should be able to POST /api/v1/resource1 (wildcard access)",
		},
		{
			name:           "Bob_GET_Resource2_Allowed",
			user:           "bob",
			method:         "GET",
			path:           "/api/v1/resource2",
			expectedStatus: http.StatusOK,
			description:    "Bob should be able to GET /api/v1/resource2",
		},
		{
			name:           "Bob_POST_Data1_Allowed",
			user:           "bob",
			method:         "POST",
			path:           "/api/v1/data1",
			expectedStatus: http.StatusOK,
			description:    "Bob should be able to POST /api/v1/data1 (POST /api/v1/* permission)",
		},
		{
			name:           "Bob_GET_Data1_Denied",
			user:           "bob",
			method:         "GET",
			path:           "/api/v1/data1",
			expectedStatus: http.StatusForbidden,
			description:    "Bob should NOT be able to GET /api/v1/data1",
		},
		
		// Cathy's permissions: role dataset1_admin (access to /dataset1/*)
		{
			name:           "Cathy_GET_Dataset1_Allowed",
			user:           "cathy",
			method:         "GET",
			path:           "/dataset1/item",
			expectedStatus: http.StatusOK,
			description:    "Cathy should be able to GET /dataset1/* (dataset1_admin role)",
		},
		{
			name:           "Cathy_POST_Dataset1_Allowed",
			user:           "cathy",
			method:         "POST",
			path:           "/dataset1/item",
			expectedStatus: http.StatusOK,
			description:    "Cathy should be able to POST /dataset1/* (dataset1_admin role)",
		},
		{
			name:           "Cathy_GET_ApiV1_Denied",
			user:           "cathy",
			method:         "GET",
			path:           "/api/v1/data1",
			expectedStatus: http.StatusForbidden,
			description:    "Cathy should NOT be able to access /api/v1/* endpoints",
		},
		
		// Unauthorized user
		{
			name:           "Unknown_User_Denied",
			user:           "unknown",
			method:         "GET",
			path:           "/api/v1/",
			expectedStatus: http.StatusForbidden,
			description:    "Unknown user should be denied access",
		},
		
		// No authentication
		{
			name:           "No_Auth_Denied",
			user:           "",
			method:         "GET",
			path:           "/api/v1/",
			expectedStatus: http.StatusForbidden,
			description:    "Request without authentication should be denied",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a simple handler that returns 200 OK if authorization passes
			handler := Authorizer(e)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("authorized"))
			}))

			req := createRequestWithAuth(tt.method, tt.path, tt.user, "password")
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("%s: expected status %d, got %d - %s", 
					tt.name, tt.expectedStatus, rr.Code, tt.description)
			}
		})
	}
}

// TestHTTPEndpoints tests all HTTP endpoints with proper authorization
func TestHTTPEndpoints(t *testing.T) {
	router := setupTestRouter(t)

	tests := []struct {
		name           string
		method         string
		path           string
		user           string
		expectedStatus int
		expectedBody   string
		description    string
	}{
		// Protected endpoints - authorized users
		{
			name:           "Alice_GET_ApiV1_Root",
			method:         "GET",
			path:           "/api/v1/",
			user:           "alice",
			expectedStatus: http.StatusOK,
			expectedBody:   "bisa akses endpoint index/root",
			description:    "Alice accessing allowed endpoint",
		},
		{
			name:           "Alice_POST_ApiV1_Data1",
			method:         "POST",
			path:           "/api/v1/data1",
			user:           "alice",
			expectedStatus: http.StatusOK,
			expectedBody:   "bisa akses post endpoint data1",
			description:    "Alice posting to allowed endpoint",
		},
		{
			name:           "Bob_POST_ApiV1_Data1",
			method:         "POST",
			path:           "/api/v1/data1",
			user:           "bob",
			expectedStatus: http.StatusOK,
			expectedBody:   "bisa akses post endpoint data1",
			description:    "Bob posting to allowed endpoint",
		},
		
		// Protected endpoints - unauthorized users
		{
			name:           "Alice_GET_ApiV1_Data1_Forbidden",
			method:         "GET",
			path:           "/api/v1/data1",
			user:           "alice",
			expectedStatus: http.StatusForbidden,
			expectedBody:   "Forbidden",
			description:    "Alice accessing forbidden endpoint",
		},
		{
			name:           "Bob_GET_ApiV1_Data2_Forbidden",
			method:         "GET",
			path:           "/api/v1/data2",
			user:           "bob",
			expectedStatus: http.StatusForbidden,
			expectedBody:   "Forbidden",
			description:    "Bob accessing forbidden endpoint",
		},
		
		// Unprotected endpoints - should work for anyone
		{
			name:           "Anyone_GET_ApiV2",
			method:         "GET",
			path:           "/api/v2/",
			user:           "",
			expectedStatus: http.StatusOK,
			expectedBody:   "GET api v2",
			description:    "Unprotected endpoint accessible without auth",
		},
		{
			name:           "Anyone_POST_ApiV2_Test",
			method:         "POST",
			path:           "/api/v2/test",
			user:           "",
			expectedStatus: http.StatusOK,
			expectedBody:   "POST api v2",
			description:    "Unprotected endpoint accessible without auth",
		},
		{
			name:           "Anyone_POST_ApiV2_UpdatePolicy",
			method:         "POST",
			path:           "/api/v2/updatepolicy",
			user:           "",
			expectedStatus: http.StatusOK,
			expectedBody:   "POST api update policy",
			description:    "Policy update endpoint accessible without auth",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := createRequestWithAuth(tt.method, tt.path, tt.user, "password")
			rr := httptest.NewRecorder()

			router.ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("%s: expected status %d, got %d - %s", 
					tt.name, tt.expectedStatus, rr.Code, tt.description)
			}

			if tt.expectedBody != "" && !strings.Contains(rr.Body.String(), tt.expectedBody) {
				t.Errorf("%s: expected body to contain '%s', got '%s'", 
					tt.name, tt.expectedBody, rr.Body.String())
			}
		})
	}
}

// TestPolicyManagement tests the AddPolicy and SavePolicy functionality
func TestPolicyManagement(t *testing.T) {
	// Create a separate enforcer for policy management tests to avoid interference
	e, err := casbin.NewEnforcer("authz_model.conf", "authz_policy_test.csv")
	if err != nil {
		t.Fatalf("Failed to create enforcer: %v", err)
	}
	
	if err = e.LoadPolicy(); err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	// Test AddPolicy
	t.Run("AddPolicy_Success", func(t *testing.T) {
		// Add a new policy that doesn't exist in the original policy file
		added, err := e.AddPolicy("newuser", "/api/v1/newtest", "GET")
		if err != nil {
			t.Fatalf("AddPolicy failed: %v", err)
		}
		if !added {
			t.Error("Expected policy to be added, but it wasn't")
		}

		// Verify the policy was added
		allowed, err := e.Enforce("newuser", "/api/v1/newtest", "GET")
		if err != nil {
			t.Fatalf("Enforce failed: %v", err)
		}
		if !allowed {
			t.Error("Expected newuser to have access after adding policy")
		}
	})

	t.Run("AddPolicy_Duplicate", func(t *testing.T) {
		// Try to add the same policy again
		added, err := e.AddPolicy("newuser", "/api/v1/newtest", "GET")
		if err != nil {
			t.Fatalf("AddPolicy failed: %v", err)
		}
		if added {
			t.Error("Expected duplicate policy not to be added")
		}
	})

	t.Run("SavePolicy_Success", func(t *testing.T) {
		// Save policy should not return an error
		err := e.SavePolicy()
		if err != nil {
			t.Errorf("SavePolicy failed: %v", err)
		}
	})
}

// TestRouterSetup tests that the router is properly configured
func TestRouterSetup(t *testing.T) {
	router := setupTestRouter(t)

	// Test that router is not nil
	if router == nil {
		t.Fatal("Router should not be nil")
	}

	// Test that routes are properly registered by making requests
	testRoutes := []struct {
		method string
		path   string
	}{
		{"GET", "/api/v1/"},
		{"GET", "/api/v1/data1"},
		{"POST", "/api/v1/data1"},
		{"GET", "/api/v1/data2"},
		{"GET", "/api/v2/"},
		{"POST", "/api/v2/test"},
		{"POST", "/api/v2/updatepolicy"},
	}

	for _, route := range testRoutes {
		t.Run(fmt.Sprintf("Route_%s_%s", route.method, route.path), func(t *testing.T) {
			req := httptest.NewRequest(route.method, route.path, nil)
			rr := httptest.NewRecorder()

			router.ServeHTTP(rr, req)

			// We expect either 200 (success), 403 (forbidden), or 401 (unauthorized)
			// but NOT 404 (not found), which would indicate the route isn't registered
			if rr.Code == http.StatusNotFound {
				t.Errorf("Route %s %s returned 404 - route not properly registered", 
					route.method, route.path)
			}
		})
	}
}

// TestFinalizerFunction tests the database finalizer function
func TestFinalizerFunction(t *testing.T) {
	// Note: Since the database connection is commented out in main(),
	// we'll test the finalizer function with a nil check
	t.Run("Finalizer_NilCheck", func(t *testing.T) {
		// This test ensures the finalizer function exists and can be called
		// In a real scenario, you would test with an actual database connection
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected finalizer to panic with nil DB, but it didn't")
			}
		}()
		
		finalizer(nil)
	})
}

// TestCasbinEnforcerSetup tests that the Casbin enforcer is properly configured
func TestCasbinEnforcerSetup(t *testing.T) {
	e := setupTestEnforcer(t)

	t.Run("Enforcer_NotNil", func(t *testing.T) {
		if e == nil {
			t.Fatal("Enforcer should not be nil")
		}
	})

	t.Run("Enforcer_LoadedPolicies", func(t *testing.T) {
		// Test that policies are loaded by checking known permissions
		policies, err := e.GetPolicy()
		if err != nil {
			t.Fatalf("GetPolicy failed: %v", err)
		}
		if len(policies) == 0 {
			t.Error("Expected policies to be loaded, but none found")
		}

		// Check for specific policies from authz_policy.csv
		expectedPolicies := [][]string{
			{"alice", "/api/v1/", "GET"},
			{"alice", "/api/v1/data1", "POST"},
			{"bob", "/api/v1/resource1", "*"},
			{"bob", "/api/v1/resource2", "GET"},
			{"bob", "/api/v1/*", "POST"},
			{"dataset1_admin", "/dataset1/*", "*"},
		}

		for _, expected := range expectedPolicies {
			found := false
			for _, policy := range policies {
				if len(policy) >= 3 && 
					policy[0] == expected[0] && 
					policy[1] == expected[1] && 
					policy[2] == expected[2] {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Expected policy not found: %v", expected)
			}
		}
	})

	t.Run("Enforcer_RoleInheritance", func(t *testing.T) {
		// Test that cathy has the dataset1_admin role
		roles, err := e.GetRolesForUser("cathy")
		if err != nil {
			t.Fatalf("GetRolesForUser failed: %v", err)
		}
		found := false
		for _, role := range roles {
			if role == "dataset1_admin" {
				found = true
				break
			}
		}
		if !found {
			t.Error("Expected cathy to have dataset1_admin role")
		}
	})
}




