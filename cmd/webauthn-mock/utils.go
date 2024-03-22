package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
)

func decodeChallenge(challenge string) []byte {
	decoded, err := base64.RawURLEncoding.DecodeString(challenge)
	if err != nil {
		panic(fmt.Sprintf("Error decoding Base64 URL string: %v", err))
	}
	return decoded
}

func encodeChallenge(challenge []byte) string {
	return base64.RawURLEncoding.EncodeToString(challenge)
}

func generateUserID() string {
	// Generate a UUID
	uuidObj, err := uuid.NewRandom()

	if err != nil {
		panic(fmt.Sprintf("Failed to generate UUID: %v", err))
	}

	// Encode the UUID to base64 URL encoding
	encodedUUID := base64.RawURLEncoding.EncodeToString(uuidObj[:])

	return encodedUUID
}

// Custom JSON marshaling to handle specific fields
func (w WebAuthnRegister) MarshalJSON() ([]byte, error) {
	// Temp struct to avoid recursion
	type Alias WebAuthnRegister

	// Unmarshal the config and response strings back to raw JSON for proper formatting
	var configRaw json.RawMessage
	if w.WebauthnConfig != "" {
		if err := json.Unmarshal([]byte(w.WebauthnConfig), &configRaw); err != nil {
			return nil, err
		}
	}

	var responseRaw json.RawMessage
	if w.WebauthnResponse != "" {
		if err := json.Unmarshal([]byte(w.WebauthnResponse), &responseRaw); err != nil {
			return nil, err
		}
	}

	// Use the Alias type to marshal all but the special fields, then add those fields manually
	return json.Marshal(&struct {
		Config   json.RawMessage `json:"config,omitempty"`
		Response json.RawMessage `json:"response,omitempty"`
		*Alias
	}{
		Config:   configRaw,
		Response: responseRaw,
		Alias:    (*Alias)(&w),
	})
}
