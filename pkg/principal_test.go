package connect_permify_propelauth

import (
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/propelauth/propelauth-go/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test cases for newPrincipalFromApiKey function
func TestNewPrincipalFromApiKey(t *testing.T) {
	t.Run("WithCompleteUserAndOrg", func(t *testing.T) {
		userID := uuid.New()
		orgID := uuid.New()
		username := "testuser"
		firstName := "Test"
		lastName := "User"
		email := "test@example.com"

		userMetadata := map[string]any{"role": "admin", "department": "engineering"}
		userProperties := map[string]any{"theme": "dark", "notifications": true}
		orgMetadata := map[string]any{"plan": "enterprise", "region": "us-east-1"}

		orgMemberInfo := &models.OrgMemberInfoFromToken{
			OrgID:   orgID,
			OrgName: "Test Organization",
		}

		apiKey := &models.APIKeyValidation{
			User: &models.UserMetadata{
				UserID:     userID,
				Email:      email,
				Username:   &username,
				FirstName:  &firstName,
				LastName:   &lastName,
				Metadata:   &userMetadata,
				Properties: &userProperties,
			},
			Org: &models.APIKeyOrgMetadata{
				OrgID:    orgID,
				OrgName:  "Test Organization",
				Metadata: orgMetadata,
			},
			UserInOrg: orgMemberInfo,
		}

		principal := newPrincipalFromApiKey(apiKey)

		require.NotNil(t, principal)

		// Test user data
		require.NotNil(t, principal.User)
		assert.Equal(t, userID, principal.User.ID)
		assert.Equal(t, email, principal.User.Email)
		assert.Equal(t, username, principal.User.Username)
		assert.Equal(t, firstName, *principal.User.FirstName)
		assert.Equal(t, lastName, *principal.User.LastName)
		assert.Equal(t, userMetadata, principal.User.Metadata)
		assert.Equal(t, userProperties, principal.User.Properties)

		// Test organization data
		require.NotNil(t, principal.ActiveOrg)
		assert.Equal(t, orgID, principal.ActiveOrg.ID)
		assert.Equal(t, "Test Organization", principal.ActiveOrg.Name)
		assert.Equal(t, orgMetadata, principal.ActiveOrg.Metadata)

		// Test user in org data
		assert.Equal(t, orgMemberInfo, principal.UserInOrg)
	})

	t.Run("WithUserNoOrg", func(t *testing.T) {
		userID := uuid.New()
		email := "test@example.com"

		apiKey := &models.APIKeyValidation{
			User: &models.UserMetadata{
				UserID: userID,
				Email:  email,
			},
			Org:       nil,
			UserInOrg: nil,
		}

		principal := newPrincipalFromApiKey(apiKey)

		require.NotNil(t, principal)

		// Test user data
		require.NotNil(t, principal.User)
		assert.Equal(t, userID, principal.User.ID)
		assert.Equal(t, email, principal.User.Email)
		assert.Equal(t, email, principal.User.Username) // Should default to email
		assert.Nil(t, principal.User.FirstName)
		assert.Nil(t, principal.User.LastName)
		assert.Empty(t, principal.User.Metadata)
		assert.Empty(t, principal.User.Properties)

		// Test no organization data
		assert.Nil(t, principal.ActiveOrg)
		assert.Nil(t, principal.UserInOrg)
	})

	t.Run("NoUserWithOrg", func(t *testing.T) {
		orgID := uuid.New()
		orgMetadata := map[string]any{"plan": "basic"}

		apiKey := &models.APIKeyValidation{
			User: nil,
			Org: &models.APIKeyOrgMetadata{
				OrgID:    orgID,
				OrgName:  "Test Organization",
				Metadata: orgMetadata,
			},
			UserInOrg: nil,
		}

		principal := newPrincipalFromApiKey(apiKey)

		require.NotNil(t, principal)

		// Test no user data
		assert.Nil(t, principal.User)

		// Test organization data
		require.NotNil(t, principal.ActiveOrg)
		assert.Equal(t, orgID, principal.ActiveOrg.ID)
		assert.Equal(t, "Test Organization", principal.ActiveOrg.Name)
		assert.Equal(t, orgMetadata, principal.ActiveOrg.Metadata)

		assert.Nil(t, principal.UserInOrg)
	})

	t.Run("NoUserNoOrg", func(t *testing.T) {
		apiKey := &models.APIKeyValidation{
			User:      nil,
			Org:       nil,
			UserInOrg: nil,
		}

		principal := newPrincipalFromApiKey(apiKey)

		require.NotNil(t, principal)
		assert.Nil(t, principal.User)
		assert.Nil(t, principal.ActiveOrg)
		assert.Nil(t, principal.UserInOrg)
	})

	t.Run("NilMetadataAndProperties", func(t *testing.T) {
		userID := uuid.New()
		email := "test@example.com"

		apiKey := &models.APIKeyValidation{
			User: &models.UserMetadata{
				UserID:     userID,
				Email:      email,
				Metadata:   nil, // Nil metadata
				Properties: nil, // Nil properties
			},
		}

		principal := newPrincipalFromApiKey(apiKey)

		require.NotNil(t, principal)
		require.NotNil(t, principal.User)
		assert.Empty(t, principal.User.Metadata)
		assert.Empty(t, principal.User.Properties)
	})

	t.Run("EmptyMetadataAndProperties", func(t *testing.T) {
		userID := uuid.New()
		email := "test@example.com"
		emptyMetadata := map[string]any{}
		emptyProperties := map[string]any{}

		apiKey := &models.APIKeyValidation{
			User: &models.UserMetadata{
				UserID:     userID,
				Email:      email,
				Metadata:   &emptyMetadata,
				Properties: &emptyProperties,
			},
		}

		principal := newPrincipalFromApiKey(apiKey)

		require.NotNil(t, principal)
		require.NotNil(t, principal.User)
		assert.Equal(t, emptyMetadata, principal.User.Metadata)
		assert.Equal(t, emptyProperties, principal.User.Properties)
	})

	t.Run("NilUsername", func(t *testing.T) {
		userID := uuid.New()
		email := "test@example.com"

		apiKey := &models.APIKeyValidation{
			User: &models.UserMetadata{
				UserID:   userID,
				Email:    email,
				Username: nil, // Nil username
			},
		}

		principal := newPrincipalFromApiKey(apiKey)

		require.NotNil(t, principal)
		require.NotNil(t, principal.User)
		assert.Equal(t, email, principal.User.Username) // Should default to email
	})

	t.Run("EmptyUsername", func(t *testing.T) {
		userID := uuid.New()
		email := "test@example.com"
		emptyUsername := ""

		apiKey := &models.APIKeyValidation{
			User: &models.UserMetadata{
				UserID:   userID,
				Email:    email,
				Username: &emptyUsername, // Empty username
			},
		}

		principal := newPrincipalFromApiKey(apiKey)

		require.NotNil(t, principal)
		require.NotNil(t, principal.User)
		assert.Equal(t, emptyUsername, principal.User.Username) // Should use empty string
	})

	t.Run("NilOrgMetadata", func(t *testing.T) {
		orgID := uuid.New()

		apiKey := &models.APIKeyValidation{
			Org: &models.APIKeyOrgMetadata{
				OrgID:    orgID,
				OrgName:  "Test Organization",
				Metadata: nil, // Nil org metadata
			},
		}

		principal := newPrincipalFromApiKey(apiKey)

		require.NotNil(t, principal)
		require.NotNil(t, principal.ActiveOrg)
		assert.Nil(t, principal.ActiveOrg.Metadata)
	})

	t.Run("EmptyOrgMetadata", func(t *testing.T) {
		orgID := uuid.New()
		emptyMetadata := map[string]any{}

		apiKey := &models.APIKeyValidation{
			Org: &models.APIKeyOrgMetadata{
				OrgID:    orgID,
				OrgName:  "Test Organization",
				Metadata: emptyMetadata,
			},
		}

		principal := newPrincipalFromApiKey(apiKey)

		require.NotNil(t, principal)
		require.NotNil(t, principal.ActiveOrg)
		assert.Equal(t, emptyMetadata, principal.ActiveOrg.Metadata)
	})
}

// Test cases for newPrincipalFromToken function
func TestNewPrincipalFromToken(t *testing.T) {
	t.Run("WithCompleteUserAndOrg", func(t *testing.T) {
		userID := uuid.New()
		orgID := uuid.New()
		email := "test@example.com"
		username := "testuser"
		firstName := "Test"
		lastName := "User"

		userMetadata := map[string]any{"role": "admin", "department": "engineering"}
		userProperties := map[string]any{"theme": "dark", "notifications": true}
		orgMetadata := map[string]any{"plan": "enterprise", "region": "us-east-1"}

		orgMemberInfo := &models.OrgMemberInfoFromToken{
			OrgID:       orgID,
			OrgName:     "Test Organization",
			OrgMetadata: orgMetadata,
		}

		user := &models.UserFromToken{
			UserID:        userID,
			Email:         &email,
			Username:      &username,
			FirstName:     &firstName,
			LastName:      &lastName,
			Metadata:      userMetadata,
			Properties:    userProperties,
			OrgMemberInfo: orgMemberInfo,
		}

		principal := newPrincipalFromToken(user)

		require.NotNil(t, principal)

		// Test user data
		require.NotNil(t, principal.User)
		assert.Equal(t, userID, principal.User.ID)
		assert.Equal(t, email, principal.User.Email)
		assert.Equal(t, username, principal.User.Username)
		assert.Equal(t, firstName, *principal.User.FirstName)
		assert.Equal(t, lastName, *principal.User.LastName)
		assert.Equal(t, userMetadata, principal.User.Metadata)
		assert.Equal(t, userProperties, principal.User.Properties)

		// Test organization data
		require.NotNil(t, principal.ActiveOrg)
		assert.Equal(t, orgID, principal.ActiveOrg.ID)
		assert.Equal(t, "Test Organization", principal.ActiveOrg.Name)
		assert.Equal(t, orgMetadata, principal.ActiveOrg.Metadata)

		// Test user in org data
		assert.Equal(t, orgMemberInfo, principal.UserInOrg)
	})

	t.Run("WithUserNoOrg", func(t *testing.T) {
		userID := uuid.New()
		email := "test@example.com"
		username := "testuser"

		user := &models.UserFromToken{
			UserID:        userID,
			Email:         &email,
			Username:      &username,
			OrgMemberInfo: nil, // No org info
		}

		principal := newPrincipalFromToken(user)

		require.NotNil(t, principal)

		// Test user data
		require.NotNil(t, principal.User)
		assert.Equal(t, userID, principal.User.ID)
		assert.Equal(t, email, principal.User.Email)
		assert.Equal(t, username, principal.User.Username)

		// Test no organization data
		assert.Nil(t, principal.ActiveOrg)
		assert.Nil(t, principal.UserInOrg)
	})

	t.Run("NilUsername", func(t *testing.T) {
		userID := uuid.New()
		email := "test@example.com"

		user := &models.UserFromToken{
			UserID:   userID,
			Email:    &email,
			Username: nil, // Nil username
		}

		principal := newPrincipalFromToken(user)

		require.NotNil(t, principal)
		require.NotNil(t, principal.User)
		assert.Equal(t, email, principal.User.Username) // Should default to email
	})

	t.Run("EmptyUsername", func(t *testing.T) {
		userID := uuid.New()
		email := "test@example.com"
		emptyUsername := ""

		user := &models.UserFromToken{
			UserID:   userID,
			Email:    &email,
			Username: &emptyUsername, // Empty username
		}

		principal := newPrincipalFromToken(user)

		require.NotNil(t, principal)
		require.NotNil(t, principal.User)
		assert.Equal(t, emptyUsername, principal.User.Username) // Should use empty string
	})

	t.Run("NilMetadataAndProperties", func(t *testing.T) {
		userID := uuid.New()
		email := "test@example.com"

		user := &models.UserFromToken{
			UserID:     userID,
			Email:      &email,
			Metadata:   nil, // Nil metadata
			Properties: nil, // Nil properties
		}

		principal := newPrincipalFromToken(user)

		require.NotNil(t, principal)
		require.NotNil(t, principal.User)
		assert.Nil(t, principal.User.Metadata)
		assert.Nil(t, principal.User.Properties)
	})

	t.Run("EmptyMetadataAndProperties", func(t *testing.T) {
		userID := uuid.New()
		email := "test@example.com"
		emptyMetadata := map[string]any{}
		emptyProperties := map[string]any{}

		user := &models.UserFromToken{
			UserID:     userID,
			Email:      &email,
			Metadata:   emptyMetadata,
			Properties: emptyProperties,
		}

		principal := newPrincipalFromToken(user)

		require.NotNil(t, principal)
		require.NotNil(t, principal.User)
		assert.Equal(t, emptyMetadata, principal.User.Metadata)
		assert.Equal(t, emptyProperties, principal.User.Properties)
	})

	t.Run("NilFirstNameAndLastName", func(t *testing.T) {
		userID := uuid.New()
		email := "test@example.com"

		user := &models.UserFromToken{
			UserID:    userID,
			Email:     &email,
			FirstName: nil, // Nil first name
			LastName:  nil, // Nil last name
		}

		principal := newPrincipalFromToken(user)

		require.NotNil(t, principal)
		require.NotNil(t, principal.User)
		assert.Nil(t, principal.User.FirstName)
		assert.Nil(t, principal.User.LastName)
	})

	t.Run("EmptyFirstNameAndLastName", func(t *testing.T) {
		userID := uuid.New()
		email := "test@example.com"
		emptyFirstName := ""
		emptyLastName := ""

		user := &models.UserFromToken{
			UserID:    userID,
			Email:     &email,
			FirstName: &emptyFirstName,
			LastName:  &emptyLastName,
		}

		principal := newPrincipalFromToken(user)

		require.NotNil(t, principal)
		require.NotNil(t, principal.User)
		assert.Equal(t, emptyFirstName, *principal.User.FirstName)
		assert.Equal(t, emptyLastName, *principal.User.LastName)
	})

	t.Run("NilOrgMetadata", func(t *testing.T) {
		userID := uuid.New()
		orgID := uuid.New()
		email := "test@example.com"

		orgMemberInfo := &models.OrgMemberInfoFromToken{
			OrgID:       orgID,
			OrgName:     "Test Organization",
			OrgMetadata: nil, // Nil org metadata
		}

		user := &models.UserFromToken{
			UserID:        userID,
			Email:         &email,
			OrgMemberInfo: orgMemberInfo,
		}

		principal := newPrincipalFromToken(user)

		require.NotNil(t, principal)
		require.NotNil(t, principal.ActiveOrg)
		assert.Nil(t, principal.ActiveOrg.Metadata)
	})

	t.Run("EmptyOrgMetadata", func(t *testing.T) {
		userID := uuid.New()
		orgID := uuid.New()
		email := "test@example.com"
		emptyMetadata := map[string]any{}

		orgMemberInfo := &models.OrgMemberInfoFromToken{
			OrgID:       orgID,
			OrgName:     "Test Organization",
			OrgMetadata: emptyMetadata,
		}

		user := &models.UserFromToken{
			UserID:        userID,
			Email:         &email,
			OrgMemberInfo: orgMemberInfo,
		}

		principal := newPrincipalFromToken(user)

		require.NotNil(t, principal)
		require.NotNil(t, principal.ActiveOrg)
		assert.Equal(t, emptyMetadata, principal.ActiveOrg.Metadata)
	})

	t.Run("NilAPIKeyValidation", func(t *testing.T) {
		// This will panic due to nil pointer dereference, which is expected behavior
		assert.Panics(t, func() {
			newPrincipalFromApiKey(nil)
		})
	})

	t.Run("UnicodeInUserData", func(t *testing.T) {
		userID := uuid.New()
		email := "测试@example.com"
		username := "用户名"
		firstName := "测试"
		lastName := "用户"

		apiKey := &models.APIKeyValidation{
			User: &models.UserMetadata{
				UserID:    userID,
				Email:     email,
				Username:  &username,
				FirstName: &firstName,
				LastName:  &lastName,
			},
		}

		principal := newPrincipalFromApiKey(apiKey)

		require.NotNil(t, principal)
		require.NotNil(t, principal.User)
		assert.Equal(t, email, principal.User.Email)
		assert.Equal(t, username, principal.User.Username)
		assert.Equal(t, firstName, *principal.User.FirstName)
		assert.Equal(t, lastName, *principal.User.LastName)
	})

	t.Run("UnicodeInOrgData", func(t *testing.T) {
		orgID := uuid.New()
		orgName := "测试组织"
		orgMetadata := map[string]any{"地区": "中国", "类型": "企业"}

		apiKey := &models.APIKeyValidation{
			Org: &models.APIKeyOrgMetadata{
				OrgID:    orgID,
				OrgName:  orgName,
				Metadata: orgMetadata,
			},
		}

		principal := newPrincipalFromApiKey(apiKey)

		require.NotNil(t, principal)
		require.NotNil(t, principal.ActiveOrg)
		assert.Equal(t, orgName, principal.ActiveOrg.Name)
		assert.Equal(t, orgMetadata, principal.ActiveOrg.Metadata)
	})
}

// Additional edge case tests for newPrincipalFromToken
func TestNewPrincipalFromTokenEdgeCases(t *testing.T) {
	t.Run("NilUserFromToken", func(t *testing.T) {
		// This will panic due to nil pointer dereference, which is expected behavior
		assert.Panics(t, func() {
			newPrincipalFromToken(nil)
		})
	})

	t.Run("UnicodeInUserData", func(t *testing.T) {
		userID := uuid.New()
		email := "测试@example.com"
		username := "用户名"
		firstName := "测试"
		lastName := "用户"

		user := &models.UserFromToken{
			UserID:    userID,
			Email:     &email,
			Username:  &username,
			FirstName: &firstName,
			LastName:  &lastName,
		}

		principal := newPrincipalFromToken(user)

		require.NotNil(t, principal)
		require.NotNil(t, principal.User)
		assert.Equal(t, email, principal.User.Email)
		assert.Equal(t, username, principal.User.Username)
		assert.Equal(t, firstName, *principal.User.FirstName)
		assert.Equal(t, lastName, *principal.User.LastName)
	})

	t.Run("UnicodeInOrgData", func(t *testing.T) {
		userID := uuid.New()
		orgID := uuid.New()
		email := "test@example.com"
		orgName := "测试组织"
		orgMetadata := map[string]any{"地区": "中国", "类型": "企业"}

		orgMemberInfo := &models.OrgMemberInfoFromToken{
			OrgID:       orgID,
			OrgName:     orgName,
			OrgMetadata: orgMetadata,
		}

		user := &models.UserFromToken{
			UserID:        userID,
			Email:         &email,
			OrgMemberInfo: orgMemberInfo,
		}

		principal := newPrincipalFromToken(user)

		require.NotNil(t, principal)
		require.NotNil(t, principal.ActiveOrg)
		assert.Equal(t, orgName, principal.ActiveOrg.Name)
		assert.Equal(t, orgMetadata, principal.ActiveOrg.Metadata)
	})

	t.Run("VeryLongStringValues", func(t *testing.T) {
		userID := uuid.New()

		// Create a long email prefix
		longEmailPrefix := strings.Repeat("a", 1000)
		longEmail := longEmailPrefix + "@example.com"

		// Create a long username
		longUsername := strings.Repeat("u", 500)

		user := &models.UserFromToken{
			UserID:   userID,
			Email:    &longEmail,
			Username: &longUsername,
		}

		principal := newPrincipalFromToken(user)

		require.NotNil(t, principal)
		require.NotNil(t, principal.User)
		assert.Equal(t, longEmail, principal.User.Email)
		assert.Equal(t, longUsername, principal.User.Username)
		assert.Len(t, principal.User.Email, 1012) // 1000 + "@example.com" (12 chars)
		assert.Len(t, principal.User.Username, 500)
	})
}
