package connect_permify_propelauth

import (
	"testing"

	"github.com/propelauth/propelauth-go/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

	t.Run("NilMetadata", func(t *testing.T) {
		extractor := DefaultIDExtractor("service_id")
		validation := &models.APIKeyValidation{
			Metadata: nil, // Nil metadata map
		}

		id, err := extractor(validation)

		require.Error(t, err)
		assert.Empty(t, id)
		assert.Contains(t, err.Error(), "service_id not found in api key metadata")
	})

	t.Run("EmptyMetadata", func(t *testing.T) {
		extractor := DefaultIDExtractor("service_id")
		validation := &models.APIKeyValidation{
			Metadata: map[string]any{}, // Empty metadata map
		}

		id, err := extractor(validation)

		require.Error(t, err)
		assert.Empty(t, id)
		assert.Contains(t, err.Error(), "service_id not found in api key metadata")
	})

	t.Run("EmptyStringValue", func(t *testing.T) {
		extractor := DefaultIDExtractor("service_id")
		validation := &models.APIKeyValidation{
			Metadata: map[string]any{"service_id": ""}, // Empty string value
		}

		id, err := extractor(validation)

		require.NoError(t, err)
		assert.Equal(t, "", id) // Should return empty string, not error
	})

	t.Run("NilValue", func(t *testing.T) {
		extractor := DefaultIDExtractor("service_id")
		validation := &models.APIKeyValidation{
			Metadata: map[string]any{"service_id": nil}, // Nil value
		}

		// This will panic due to type assertion on nil, which is expected behavior
		assert.Panics(t, func() {
			extractor(validation)
		})
	})

	t.Run("BooleanValue", func(t *testing.T) {
		extractor := DefaultIDExtractor("is_active")
		validation := &models.APIKeyValidation{
			Metadata: map[string]any{"is_active": true}, // Boolean value
		}

		// This will panic due to type assertion, which is expected behavior
		assert.Panics(t, func() {
			extractor(validation)
		})
	})

	t.Run("SliceValue", func(t *testing.T) {
		extractor := DefaultIDExtractor("tags")
		validation := &models.APIKeyValidation{
			Metadata: map[string]any{"tags": []string{"tag1", "tag2"}}, // Slice value
		}

		// This will panic due to type assertion, which is expected behavior
		assert.Panics(t, func() {
			extractor(validation)
		})
	})

	t.Run("MapValue", func(t *testing.T) {
		extractor := DefaultIDExtractor("config")
		validation := &models.APIKeyValidation{
			Metadata: map[string]any{"config": map[string]string{"key": "value"}}, // Map value
		}

		// This will panic due to type assertion, which is expected behavior
		assert.Panics(t, func() {
			extractor(validation)
		})
	})

	t.Run("EmptyMetadataKey", func(t *testing.T) {
		extractor := DefaultIDExtractor("") // Empty key
		validation := &models.APIKeyValidation{
			Metadata: map[string]any{"": "empty-key-value", "service_id": "test-service"},
		}

		id, err := extractor(validation)

		require.NoError(t, err)
		assert.Equal(t, "empty-key-value", id) // Should work with empty key
	})

	t.Run("SpecialCharactersInKey", func(t *testing.T) {
		extractor := DefaultIDExtractor("service-id.with_special@chars")
		validation := &models.APIKeyValidation{
			Metadata: map[string]any{"service-id.with_special@chars": "special-service-123"},
		}

		id, err := extractor(validation)

		require.NoError(t, err)
		assert.Equal(t, "special-service-123", id)
	})

	t.Run("UnicodeValue", func(t *testing.T) {
		extractor := DefaultIDExtractor("unicode_id")
		validation := &models.APIKeyValidation{
			Metadata: map[string]any{"unicode_id": "服务-123-🚀"}, // Unicode string
		}

		id, err := extractor(validation)

		require.NoError(t, err)
		assert.Equal(t, "服务-123-🚀", id)
	})

	t.Run("VeryLongValue", func(t *testing.T) {
		extractor := DefaultIDExtractor("long_id")
		longValue := string(make([]byte, 10000)) // Very long string
		for i := range longValue {
			longValue = longValue[:i] + "a" + longValue[i+1:]
		}
		validation := &models.APIKeyValidation{
			Metadata: map[string]any{"long_id": longValue},
		}

		id, err := extractor(validation)

		require.NoError(t, err)
		assert.Equal(t, longValue, id)
		assert.Len(t, id, 10000)
	})

	t.Run("NilValidation", func(t *testing.T) {
		extractor := DefaultIDExtractor("service_id")

		// This will panic due to nil pointer dereference, which is expected behavior
		assert.Panics(t, func() {
			extractor(nil)
		})
	})

	t.Run("CaseSensitiveKey", func(t *testing.T) {
		extractor := DefaultIDExtractor("Service_ID") // Different case
		validation := &models.APIKeyValidation{
			Metadata: map[string]any{
				"service_id": "lowercase-service",
				"Service_ID": "mixed-case-service",
				"SERVICE_ID": "uppercase-service",
			},
		}

		id, err := extractor(validation)

		require.NoError(t, err)
		assert.Equal(t, "mixed-case-service", id) // Should match exact case
	})

	t.Run("NumericStringValue", func(t *testing.T) {
		extractor := DefaultIDExtractor("numeric_string_id")
		validation := &models.APIKeyValidation{
			Metadata: map[string]any{"numeric_string_id": "12345"}, // Numeric string
		}

		id, err := extractor(validation)

		require.NoError(t, err)
		assert.Equal(t, "12345", id)
	})
}
