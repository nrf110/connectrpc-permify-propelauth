package connect_permify_propelauth

import (
	"context"
	"errors"
	"strings"

	"connectrpc.com/connect"
	connectpermify "github.com/nrf110/connectrpc-permify/pkg"
	propelauth "github.com/propelauth/propelauth-go/pkg"
)

type PropelConfig struct {
	ApiKey  string
	AuthURL string
}

type PropelAuthenticator struct {
	client      propelauth.ClientInterface
	idExtractor IDExtractor
}

type principalKey struct{}

var PrincipalKey principalKey = principalKey{}

func GetPrincipal(ctx context.Context) *PropelAuthPrincipal {
	return ctx.Value(PrincipalKey).(*PropelAuthPrincipal)
}

func NewPropelAuthenticator(config PropelConfig, idExtractor IDExtractor) (*PropelAuthenticator, error) {
	client, err := propelauth.InitBaseAuth(config.AuthURL, config.ApiKey, nil)
	if err != nil {
		return nil, err
	}

	return &PropelAuthenticator{
		client:      client,
		idExtractor: idExtractor,
	}, nil
}

func (propel *PropelAuthenticator) Authenticate(ctx context.Context, req connect.AnyRequest) (*connectpermify.AuthenticationResult, error) {
	if oauthTokenHeader := req.Header().Get("Authorization"); oauthTokenHeader != "" {
		return propel.getUserFromToken(ctx, req)
	}

	if apiKey := req.Header().Get("X-Api-Key"); apiKey != "" {
		return propel.getPrincipalFromApiKey(ctx, apiKey)
	}

	return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthenticated"))
}

func (propel *PropelAuthenticator) getUserFromToken(ctx context.Context, req connect.AnyRequest) (*connectpermify.AuthenticationResult, error) {
	user, err := propel.client.GetUser(req.Header().Get("Authorization"))
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid token"))
	}

	principal := newPrincipalFromToken(user)

	return &connectpermify.AuthenticationResult{
		Principal: &connectpermify.Resource{
			Type:       "User",
			ID:         principal.User.ID.String(),
			Attributes: principal.User.Properties,
		},
		Context: context.WithValue(ctx, PrincipalKey, principal),
	}, nil
}

func (propel *PropelAuthenticator) getPrincipalFromApiKey(ctx context.Context, apiKey string) (*connectpermify.AuthenticationResult, error) {
	result, err := propel.client.ValidateAPIKey(strings.TrimSpace(apiKey))
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid api key"))
	}

	principal := newPrincipalFromApiKey(result)

	if principal.User != nil {
		return &connectpermify.AuthenticationResult{
			Principal: &connectpermify.Resource{
				Type:       "User",
				ID:         principal.User.ID.String(),
				Attributes: principal.User.Properties,
			},
			Context: context.WithValue(ctx, PrincipalKey, principal),
		}, nil
	}

	id, err := propel.idExtractor(result)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthenticated"))
	}

	return &connectpermify.AuthenticationResult{
		Principal: &connectpermify.Resource{
			Type:       "ApiKey",
			ID:         id,
			Attributes: result.Metadata,
		},
		Context: context.WithValue(ctx, PrincipalKey, principal),
	}, nil
}
