package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

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

// HexBytes wraps a byte slice to implement flag.Value interface.
type HexBytes []byte

// Set is part of the flag.Value interface. It decodes a hex string and stores the bytes.
func (h *HexBytes) Set(s string) error {
	// Check and remove the "0x" prefix if present
	challenge := strings.TrimPrefix(s, "0x")

	// Decode the hex string
	bytes, err := hex.DecodeString(challenge)
	if err != nil {
		return err
	}
	*h = bytes
	return nil
}

// String is part of the flag.Value interface. It returns the hex string representation.
func (h *HexBytes) String() string {
	return hex.EncodeToString(*h)
}
