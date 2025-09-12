package connect_permify_propelauth

import (
	"fmt"

	"github.com/propelauth/propelauth-go/pkg/models"
)

type IDExtractor func(*models.APIKeyValidation) (string, error)

func DefaultIDExtractor(metadataKey string) func(*models.APIKeyValidation) (string, error) {
	return func(validation *models.APIKeyValidation) (string, error) {
		id, found := validation.Metadata[metadataKey]
		if found {
			return id.(string), nil
		}

		return "", fmt.Errorf("%s not found in api key metadata", metadataKey)
	}
}
