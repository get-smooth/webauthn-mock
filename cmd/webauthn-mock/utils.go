package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/google/uuid"
)

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

func encodeToHex(data []byte) string {
	return "0x" + hex.EncodeToString(data)
}
