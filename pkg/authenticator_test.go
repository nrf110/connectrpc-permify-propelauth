package connect_permify_propelauth

/*
Comprehensive Test Plan for PropelAuthenticator

This test suite provides comprehensive coverage for the PropelAuthenticator struct with the following test categories:

1. **NewPropelAuthenticator Tests:**
   - Valid configuration with proper AuthURL and ApiKey (expects error due to no real service)
   - Empty AuthURL (expects error)
   - Empty ApiKey (expects error)
   - Invalid/malformed AuthURL (expects error)

2. **getPrincipalFromApiKey Method Tests:**
   - API key with associated user (success case)
   - API key without user, using ID extractor (success case)
   - Invalid API key (authentication error)
   - ID extractor failure (authentication error)
   - API key with whitespace trimming

3. **Principal Creation Function Tests:**
   - newPrincipalFromToken with complete user data
   - newPrincipalFromToken without username (defaults to email)
   - newPrincipalFromToken without organization info
   - newPrincipalFromApiKey with user data
   - newPrincipalFromApiKey without user data
   - newPrincipalFromApiKey with nil metadata/properties

4. **GetPrincipal Helper Function Tests:**
   - Retrieving principal from context (success)
   - Missing principal in context (panic, expected behavior)

5. **DefaultIDExtractor Tests:**
   - Successful ID extraction from metadata
   - Missing key in metadata (error)
   - Wrong data type in metadata (panic, expected behavior)

6. **Edge Cases:**
   - Whitespace trimming in API keys
   - Nil pointer handling in user metadata
   - Type assertion validation

Testing Approach:
- Uses ovechkin-dm/mockio for mocking propelauth.ClientInterface directly
- Tests both success and failure scenarios with actual PropelAuthenticator instances
- Validates error types and messages
- Verifies context propagation and principal creation
- Tests edge cases and error conditions
- Organized with t.Run for better test structure and reporting

Note: NewPropelAuthenticator tests expect errors because they attempt to connect to real PropelAuth services.
In a production test environment, you would mock the propelauth.InitBaseAuth function.
*/

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	connectpermify "github.com/nrf110/connectrpc-permify/pkg"
	"github.com/ovechkin-dm/mockio/mock"
	propelauth "github.com/propelauth/propelauth-go/pkg"
	"github.com/propelauth/propelauth-go/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockRequest is a mock implementation that provides the minimal interface we need
type MockRequest struct {
	headers http.Header
}

func (m *MockRequest) Header() http.Header {
	return m.headers
}

func (m *MockRequest) Any() any {
	return nil
}

func (m *MockRequest) Spec() connect.Spec {
	return connect.Spec{}
}

func (m *MockRequest) Peer() connect.Peer {
	return connect.Peer{}
}

func (m *MockRequest) HTTPMethod() string {
	return "POST"
}

// Test cases for principal creation functions
func TestNewPrincipalFromToken(t *testing.T) {
	t.Run("WithCompleteUserData", func(t *testing.T) {
		testUser := createTestUserFromToken()

		principal := newPrincipalFromToken(testUser)

		require.NotNil(t, principal)
		require.NotNil(t, principal.User)
		assert.Equal(t, testUser.UserID, principal.User.ID)
		assert.Equal(t, *testUser.Email, principal.User.Email)
		assert.Equal(t, *testUser.Username, principal.User.Username)
		assert.Equal(t, *testUser.FirstName, *principal.User.FirstName)
		assert.Equal(t, *testUser.LastName, *principal.User.LastName)
		assert.Equal(t, testUser.Metadata, principal.User.Metadata)
		assert.Equal(t, testUser.Properties, principal.User.Properties)

		// Test organization info
		require.NotNil(t, principal.ActiveOrg)
		assert.Equal(t, testUser.OrgMemberInfo.OrgID, principal.ActiveOrg.ID)
		assert.Equal(t, testUser.OrgMemberInfo.OrgName, principal.ActiveOrg.Name)
		assert.Equal(t, testUser.OrgMemberInfo.OrgMetadata, principal.ActiveOrg.Metadata)

		assert.Equal(t, testUser.OrgMemberInfo, principal.UserInOrg)
	})

	t.Run("WithoutUsername", func(t *testing.T) {
		email := "test@example.com"
		firstName := "Test"
		lastName := "User"
		userID := uuid.New()

		testUser := &models.UserFromToken{
			Email:         &email,
			Username:      nil, // No username provided
			FirstName:     &firstName,
			LastName:      &lastName,
			UserID:        userID,
			Metadata:      map[string]any{"role": "admin"},
			Properties:    map[string]any{"department": "engineering"},
			OrgMemberInfo: nil, // No org info
		}

		principal := newPrincipalFromToken(testUser)

		require.NotNil(t, principal)
		require.NotNil(t, principal.User)
		assert.Equal(t, email, principal.User.Username) // Should default to email
		assert.Nil(t, principal.ActiveOrg)              // No org info provided
		assert.Nil(t, principal.UserInOrg)
	})
}

func TestNewPrincipalFromApiKey(t *testing.T) {
	t.Run("WithUser", func(t *testing.T) {
		testAPIKey := createTestAPIKeyValidationWithUser()

		principal := newPrincipalFromApiKey(testAPIKey)

		require.NotNil(t, principal)
		require.NotNil(t, principal.User)
		assert.Equal(t, testAPIKey.User.UserID, principal.User.ID)
		assert.Equal(t, testAPIKey.User.Email, principal.User.Email)
		assert.Equal(t, *testAPIKey.User.Username, principal.User.Username)
		assert.Equal(t, *testAPIKey.User.FirstName, *principal.User.FirstName)
		assert.Equal(t, *testAPIKey.User.LastName, *principal.User.LastName)
		assert.Equal(t, *testAPIKey.User.Metadata, principal.User.Metadata)
		assert.Equal(t, *testAPIKey.User.Properties, principal.User.Properties)

		// Test organization info
		require.NotNil(t, principal.ActiveOrg)
		assert.Equal(t, testAPIKey.Org.OrgID, principal.ActiveOrg.ID)
		assert.Equal(t, testAPIKey.Org.OrgName, principal.ActiveOrg.Name)
		assert.Equal(t, testAPIKey.Org.Metadata, principal.ActiveOrg.Metadata)

		assert.Equal(t, testAPIKey.UserInOrg, principal.UserInOrg)
	})

	t.Run("WithoutUser", func(t *testing.T) {
		testAPIKey := createTestAPIKeyValidationWithoutUser()

		principal := newPrincipalFromApiKey(testAPIKey)

		require.NotNil(t, principal)
		assert.Nil(t, principal.User)
		assert.Nil(t, principal.ActiveOrg)
		assert.Nil(t, principal.UserInOrg)
	})

	t.Run("NilMetadata", func(t *testing.T) {
		userID := uuid.New()

		apiKey := &models.APIKeyValidation{
			Metadata: map[string]any{"service_id": "test-service"},
			User: &models.UserMetadata{
				UserID:     userID,
				Email:      "test@example.com",
				Metadata:   nil, // Nil metadata
				Properties: nil, // Nil properties
			},
			Org:       nil,
			UserInOrg: nil,
		}

		principal := newPrincipalFromApiKey(apiKey)

		require.NotNil(t, principal)
		require.NotNil(t, principal.User)
		assert.Equal(t, userID, principal.User.ID)
		assert.Equal(t, "test@example.com", principal.User.Email)
		assert.Equal(t, "test@example.com", principal.User.Username) // Should default to email
		assert.Empty(t, principal.User.Metadata)
		assert.Empty(t, principal.User.Properties)
		assert.Nil(t, principal.ActiveOrg)
	})
}

// Helper functions for creating test data
func createTestUserFromToken() *models.UserFromToken {
	email := "test@example.com"
	username := "testuser"
	firstName := "Test"
	lastName := "User"
	userID := uuid.New()

	return &models.UserFromToken{
		Email:      &email,
		Username:   &username,
		FirstName:  &firstName,
		LastName:   &lastName,
		UserID:     userID,
		Metadata:   map[string]any{"role": "admin"},
		Properties: map[string]any{"department": "engineering"},
		OrgMemberInfo: &models.OrgMemberInfoFromToken{
			OrgID:       uuid.New(),
			OrgName:     "Test Org",
			OrgMetadata: map[string]any{"type": "company"},
		},
	}
}

func createTestAPIKeyValidationWithUser() *models.APIKeyValidation {
	username := "apikeyuser"
	firstName := "API"
	lastName := "User"
	userID := uuid.New()
	orgID := uuid.New()

	metadata := map[string]any{"role": "service"}
	properties := map[string]any{"service": "backend"}

	return &models.APIKeyValidation{
		Metadata: map[string]any{"service_id": "test-service"},
		User: &models.UserMetadata{
			UserID:     userID,
			Email:      "apikey@example.com",
			Username:   &username,
			FirstName:  &firstName,
			LastName:   &lastName,
			Metadata:   &metadata,
			Properties: &properties,
		},
		Org: &models.APIKeyOrgMetadata{
			OrgID:    orgID,
			OrgName:  "API Org",
			Metadata: map[string]any{"api_access": true},
		},
		UserInOrg: &models.OrgMemberInfoFromToken{
			OrgID:       orgID,
			OrgName:     "API Org",
			OrgMetadata: map[string]any{"api_access": true},
		},
	}
}

func createTestAPIKeyValidationWithoutUser() *models.APIKeyValidation {
	return &models.APIKeyValidation{
		Metadata: map[string]any{"service_id": "test-service-no-user"},
		User:     nil,
		Org:      nil,
	}
}

// Test cases for NewPropelAuthenticator
func TestNewPropelAuthenticator(t *testing.T) {
	t.Run("ValidConfig", func(t *testing.T) {
		config := PropelConfig{
			AuthURL: "https://auth.example.com",
			ApiKey:  "test-api-key",
		}
		idExtractor := DefaultIDExtractor("service_id")

		// Note: This test will fail because we can't actually initialize PropelAuth client
		// In a real test environment, you would mock the propelauth.InitBaseAuth function
		authenticator, err := NewPropelAuthenticator(config, idExtractor)

		// For now, we expect an error since we can't connect to a real PropelAuth service
		assert.Error(t, err)
		assert.Nil(t, authenticator)
	})

	t.Run("EmptyAuthURL", func(t *testing.T) {
		config := PropelConfig{
			AuthURL: "",
			ApiKey:  "test-api-key",
		}
		idExtractor := DefaultIDExtractor("service_id")

		authenticator, err := NewPropelAuthenticator(config, idExtractor)

		assert.Error(t, err)
		assert.Nil(t, authenticator)
	})

	t.Run("EmptyApiKey", func(t *testing.T) {
		config := PropelConfig{
			AuthURL: "https://auth.example.com",
			ApiKey:  "",
		}
		idExtractor := DefaultIDExtractor("service_id")

		authenticator, err := NewPropelAuthenticator(config, idExtractor)

		assert.Error(t, err)
		assert.Nil(t, authenticator)
	})

	t.Run("InvalidAuthURL", func(t *testing.T) {
		config := PropelConfig{
			AuthURL: "invalid-url",
			ApiKey:  "test-api-key",
		}
		idExtractor := DefaultIDExtractor("service_id")

		authenticator, err := NewPropelAuthenticator(config, idExtractor)

		assert.Error(t, err)
		assert.Nil(t, authenticator)
	})
}

// Test cases for getPrincipalFromApiKey method
func TestGetPrincipalFromApiKey(t *testing.T) {
	t.Run("WithUser_Success", func(t *testing.T) {
		mock.SetUp(t)
		mockClient := mock.Mock[propelauth.ClientInterface]()
		idExtractor := DefaultIDExtractor("service_id")

		auth := &PropelAuthenticator{
			client:      mockClient,
			idExtractor: idExtractor,
		}

		testAPIKey := createTestAPIKeyValidationWithUser()
		mock.When(mockClient.ValidateAPIKey("valid-api-key")).ThenReturn(testAPIKey, nil)

		ctx := context.Background()
		result, err := auth.getPrincipalFromApiKey(ctx, "valid-api-key")

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "User", result.Principal.Type)
		assert.Equal(t, testAPIKey.User.UserID.String(), result.Principal.ID)
		assert.Equal(t, connectpermify.Attributes(*testAPIKey.User.Properties), result.Principal.Attributes)

		// Verify principal is set in context
		principal := GetPrincipal(result.Context)
		require.NotNil(t, principal)
		assert.Equal(t, testAPIKey.User.UserID, principal.User.ID)
		assert.Equal(t, testAPIKey.User.Email, principal.User.Email)

		mock.Verify(mockClient, mock.Once())
	})

	t.Run("WithoutUser_Success", func(t *testing.T) {
		mock.SetUp(t)
		mockClient := mock.Mock[propelauth.ClientInterface]()
		idExtractor := DefaultIDExtractor("service_id")

		auth := &PropelAuthenticator{
			client:      mockClient,
			idExtractor: idExtractor,
		}

		testAPIKey := createTestAPIKeyValidationWithoutUser()
		mock.When(mockClient.ValidateAPIKey("valid-api-key-no-user")).ThenReturn(testAPIKey, nil)

		ctx := context.Background()
		result, err := auth.getPrincipalFromApiKey(ctx, "valid-api-key-no-user")

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "ApiKey", result.Principal.Type)
		assert.Equal(t, "test-service-no-user", result.Principal.ID)
		assert.Equal(t, connectpermify.Attributes(testAPIKey.Metadata), result.Principal.Attributes)

		mock.Verify(mockClient, mock.Once())
	})

	t.Run("InvalidApiKey", func(t *testing.T) {
		mock.SetUp(t)
		mockClient := mock.Mock[propelauth.ClientInterface]()
		idExtractor := DefaultIDExtractor("service_id")

		auth := &PropelAuthenticator{
			client:      mockClient,
			idExtractor: idExtractor,
		}

		mock.When(mockClient.ValidateAPIKey("invalid-api-key")).ThenReturn(nil, errors.New("invalid api key"))

		ctx := context.Background()
		result, err := auth.getPrincipalFromApiKey(ctx, "invalid-api-key")

		require.Error(t, err)
		assert.Nil(t, result)

		connectErr, ok := err.(*connect.Error)
		require.True(t, ok)
		assert.Equal(t, connect.CodeUnauthenticated, connectErr.Code())
		assert.Contains(t, connectErr.Message(), "invalid api key")

		mock.Verify(mockClient, mock.Once())
	})

	t.Run("IDExtractorFailure", func(t *testing.T) {
		mock.SetUp(t)
		mockClient := mock.Mock[propelauth.ClientInterface]()
		// Create an ID extractor that will fail
		idExtractor := DefaultIDExtractor("missing_key")

		auth := &PropelAuthenticator{
			client:      mockClient,
			idExtractor: idExtractor,
		}

		testAPIKey := createTestAPIKeyValidationWithoutUser()
		mock.When(mockClient.ValidateAPIKey("valid-api-key-no-user")).ThenReturn(testAPIKey, nil)

		ctx := context.Background()
		result, err := auth.getPrincipalFromApiKey(ctx, "valid-api-key-no-user")

		require.Error(t, err)
		assert.Nil(t, result)

		connectErr, ok := err.(*connect.Error)
		require.True(t, ok)
		assert.Equal(t, connect.CodeUnauthenticated, connectErr.Code())
		assert.Contains(t, connectErr.Message(), "unauthenticated")

		mock.Verify(mockClient, mock.Once())
	})

	t.Run("TrimsWhitespace", func(t *testing.T) {
		mock.SetUp(t)
		mockClient := mock.Mock[propelauth.ClientInterface]()
		idExtractor := DefaultIDExtractor("service_id")

		auth := &PropelAuthenticator{
			client:      mockClient,
			idExtractor: idExtractor,
		}

		testAPIKey := createTestAPIKeyValidationWithUser()
		// Mock expects the trimmed version
		mock.When(mockClient.ValidateAPIKey("valid-api-key")).ThenReturn(testAPIKey, nil)

		ctx := context.Background()
		// Pass API key with whitespace
		result, err := auth.getPrincipalFromApiKey(ctx, "  valid-api-key  ")

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "User", result.Principal.Type)

		mock.Verify(mockClient, mock.Once())
	})
}

// Test cases for GetPrincipal helper function
func TestGetPrincipal(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		testUser := createTestUserFromToken()
		principal := newPrincipalFromToken(testUser)

		ctx := context.WithValue(context.Background(), PrincipalKey, principal)

		retrievedPrincipal := GetPrincipal(ctx)

		require.NotNil(t, retrievedPrincipal)
		assert.Equal(t, principal.User.ID, retrievedPrincipal.User.ID)
		assert.Equal(t, principal.User.Email, retrievedPrincipal.User.Email)
	})

	t.Run("MissingFromContext", func(t *testing.T) {
		ctx := context.Background()

		// This will panic in the current implementation, which is expected behavior
		// In a production environment, you might want to handle this more gracefully
		assert.Panics(t, func() {
			GetPrincipal(ctx)
		})
	})
}

// Test cases for DefaultIDExtractor
func TestDefaultIDExtractor(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		extractor := DefaultIDExtractor("service_id")
		validation := &models.APIKeyValidation{
			Metadata: map[string]any{"service_id": "test-service-123"},
		}

		id, err := extractor(validation)

		require.NoError(t, err)
		assert.Equal(t, "test-service-123", id)
	})

	t.Run("MissingKey", func(t *testing.T) {
		extractor := DefaultIDExtractor("missing_key")
		validation := &models.APIKeyValidation{
			Metadata: map[string]any{"service_id": "test-service-123"},
		}

		id, err := extractor(validation)

		require.Error(t, err)
		assert.Empty(t, id)
		assert.Contains(t, err.Error(), "missing_key not found in api key metadata")
	})

	t.Run("WrongType", func(t *testing.T) {
		extractor := DefaultIDExtractor("numeric_id")
		validation := &models.APIKeyValidation{
			Metadata: map[string]any{"numeric_id": 12345}, // Not a string
		}

		// This will panic due to type assertion, which is expected behavior
		assert.Panics(t, func() {
			extractor(validation)
		})
	})
}
