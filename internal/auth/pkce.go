package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
)

// PKCECodeVerifier represents a PKCE code verifier
type PKCECodeVerifier string

// PKCECodeChallenge represents a PKCE code challenge
type PKCECodeChallenge string

// GenerateCodeVerifier creates a cryptographically random code verifier
// for PKCE. The code verifier is a random string between 43-128 characters
// that uses only unreserved URL characters.
func GenerateCodeVerifier() (PKCECodeVerifier, error) {
	// Generate a random byte slice (32 bytes = 256 bits)
	// This will result in a base64 string of ~43 characters
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Encode to base64
	encoded := base64.StdEncoding.EncodeToString(b)

	// Replace characters that are not allowed in a URL
	encoded = strings.ReplaceAll(encoded, "+", "-")
	encoded = strings.ReplaceAll(encoded, "/", "_")
	encoded = strings.ReplaceAll(encoded, "=", "") // Remove padding

	return PKCECodeVerifier(encoded), nil
}

// CreateCodeChallenge creates a code challenge from the code verifier
// using the SHA256 method as specified in the PKCE standard.
func (v PKCECodeVerifier) CreateCodeChallenge() PKCECodeChallenge {
	// Create SHA256 hash of the verifier
	h := sha256.New()
	h.Write([]byte(v))
	hash := h.Sum(nil)

	// Base64url encode the hash
	encoded := base64.StdEncoding.EncodeToString(hash)

	// Replace characters that are not allowed in a URL
	encoded = strings.ReplaceAll(encoded, "+", "-")
	encoded = strings.ReplaceAll(encoded, "/", "_")
	encoded = strings.ReplaceAll(encoded, "=", "") // Remove padding

	return PKCECodeChallenge(encoded)
}

// String returns the string representation of the code verifier
func (v PKCECodeVerifier) String() string {
	return string(v)
}

// String returns the string representation of the code challenge
func (c PKCECodeChallenge) String() string {
	return string(c)
}

// VerifyCodeChallenge verifies that a code challenge matches a code verifier
func VerifyCodeChallenge(verifier PKCECodeVerifier, challenge PKCECodeChallenge) bool {
	return verifier.CreateCodeChallenge() == challenge
}
