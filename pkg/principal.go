package connect_permify_propelauth

import (
	"github.com/google/uuid"
	"github.com/propelauth/propelauth-go/pkg/models"
)

type PropelAuthUser struct {
	Email      string
	FirstName  *string
	ID         uuid.UUID
	LastName   *string
	Metadata   map[string]any
	Properties map[string]any
	Username   string
}

type PropelAuthOrg struct {
	ID       uuid.UUID
	Name     string
	Metadata map[string]any
}

type PropelAuthPrincipal struct {
	User      *PropelAuthUser
	ActiveOrg *PropelAuthOrg
	UserInOrg *models.OrgMemberInfoFromToken
}

func newPrincipalFromApiKey(apiKey *models.APIKeyValidation) *PropelAuthPrincipal {
	var (
		user      *PropelAuthUser
		activeOrg *PropelAuthOrg
	)

	if apiKey.User != nil {
		var (
			metadata   map[string]any
			properties map[string]any
			username   string = apiKey.User.Email
		)

		if apiKey.User.Metadata != nil {
			metadata = *apiKey.User.Metadata
		}

		if apiKey.User.Properties != nil {
			properties = *apiKey.User.Properties
		}

		if apiKey.User.Username != nil {
			username = *apiKey.User.Username
		}

		user = &PropelAuthUser{
			Email:      apiKey.User.Email,
			FirstName:  apiKey.User.FirstName,
			ID:         apiKey.User.UserID,
			LastName:   apiKey.User.LastName,
			Metadata:   metadata,
			Properties: properties,
			Username:   username,
		}
	}

	if apiKey.Org != nil {
		activeOrg = &PropelAuthOrg{
			ID:       apiKey.Org.OrgID,
			Name:     apiKey.Org.OrgName,
			Metadata: apiKey.Org.Metadata,
		}
	}

	return &PropelAuthPrincipal{
		User:      user,
		ActiveOrg: activeOrg,
		UserInOrg: apiKey.UserInOrg,
	}
}

func newPrincipalFromToken(user *models.UserFromToken) *PropelAuthPrincipal {
	var (
		username  string = *user.Email
		activeOrg *PropelAuthOrg
	)

	if user.Username != nil {
		username = *user.Username
	}

	if user.OrgMemberInfo != nil {
		activeOrg = &PropelAuthOrg{
			ID:       user.OrgMemberInfo.OrgID,
			Name:     user.OrgMemberInfo.OrgName,
			Metadata: user.OrgMemberInfo.OrgMetadata,
		}
	}

	return &PropelAuthPrincipal{
		User: &PropelAuthUser{
			Email:      *user.Email,
			FirstName:  user.FirstName,
			ID:         user.UserID,
			LastName:   user.LastName,
			Metadata:   user.Metadata,
			Properties: user.Properties,
			Username:   username,
		},
		ActiveOrg: activeOrg,
		UserInOrg: user.OrgMemberInfo,
	}
}
