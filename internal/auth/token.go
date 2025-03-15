package auth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/korjavin/oauth2example/internal/logger"
)

// IDTokenClaims represents the claims in an ID token
type IDTokenClaims struct {
	// Standard claims
	Issuer     string `json:"iss"`
	Subject    string `json:"sub"`
	Audience   string `json:"aud"`
	Expiration int64  `json:"exp"`
	IssuedAt   int64  `json:"iat"`

	// OpenID Connect claims
	Name          string `json:"name,omitempty"`
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
	Picture       string `json:"picture,omitempty"`
	GivenName     string `json:"given_name,omitempty"`
	FamilyName    string `json:"family_name,omitempty"`
	Locale        string `json:"locale,omitempty"`

	// Raw token parts
	rawHeader    string
	rawPayload   string
	rawSignature string
}

// ParseIDToken parses an ID token and returns the claims
func ParseIDToken(idToken string) (*IDTokenClaims, error) {
	logger.Step(9, "Parse ID Token",
		"Parsing and validating the ID token to extract user information")

	// Split the token into parts
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid ID token format: expected 3 parts, got %d", len(parts))
	}

	// Store the raw parts
	rawHeader := parts[0]
	rawPayload := parts[1]
	rawSignature := parts[2]

	// Decode the payload
	payload, err := base64URLDecode(rawPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to decode token payload: %w", err)
	}

	// Parse the claims
	var claims IDTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse token claims: %w", err)
	}

	// Store the raw parts in the claims
	claims.rawHeader = rawHeader
	claims.rawPayload = rawPayload
	claims.rawSignature = rawSignature

	logger.Educational("ID Token",
		"The ID token is a JSON Web Token (JWT) that contains claims about the user.\n"+
			"It consists of three parts separated by dots:\n\n"+
			"1. Header: Contains metadata about the token (type, algorithm)\n"+
			"2. Payload: Contains the claims (user information, expiration, etc.)\n"+
			"3. Signature: Verifies the token's authenticity\n\n"+
			"The claims in the ID token include:\n"+
			"- iss (Issuer): Who issued the token\n"+
			"- sub (Subject): The user's unique identifier\n"+
			"- aud (Audience): Who the token is intended for\n"+
			"- exp (Expiration): When the token expires\n"+
			"- iat (Issued At): When the token was issued\n"+
			"- Additional user information (name, email, etc.)")

	return &claims, nil
}

// ValidateIDToken performs basic validation of the ID token claims
func ValidateIDToken(claims *IDTokenClaims, expectedAudience string) error {
	// Check if the token is expired
	now := time.Now().Unix()
	if claims.Expiration < now {
		return fmt.Errorf("ID token is expired (exp: %d, now: %d)", claims.Expiration, now)
	}

	// Check if the token was issued in the future
	if claims.IssuedAt > now {
		return fmt.Errorf("ID token was issued in the future (iat: %d, now: %d)", claims.IssuedAt, now)
	}

	// Check the audience if expected audience is provided
	if expectedAudience != "" {
		// Handle both string and array audience formats
		var audiences []string

		// If the audience is a string
		if claims.Audience != "" {
			audiences = []string{claims.Audience}
		}

		// Check if the expected audience is in the list
		found := false
		for _, aud := range audiences {
			if aud == expectedAudience {
				found = true
				break
			}
		}

		if !found {
			return fmt.Errorf("ID token audience does not match expected audience")
		}
	}

	return nil
}

// FormatTokenInfo formats the token information for display
func FormatTokenInfo(tokenResp *TokenResponse, claims *IDTokenClaims) string {
	var sb strings.Builder

	sb.WriteString("\n=== OAuth2 Token Information ===\n\n")

	// Access Token
	sb.WriteString("Access Token:\n")
	sb.WriteString(fmt.Sprintf("  Type: %s\n", tokenResp.TokenType))
	sb.WriteString(fmt.Sprintf("  Expires In: %d seconds\n", tokenResp.ExpiresIn))

	// Truncate the access token for display
	accessToken := tokenResp.AccessToken
	if len(accessToken) > 20 {
		accessToken = accessToken[:20] + "..." + accessToken[len(accessToken)-10:]
	}
	sb.WriteString(fmt.Sprintf("  Token: %s\n\n", accessToken))

	// Refresh Token
	if tokenResp.RefreshToken != "" {
		refreshToken := tokenResp.RefreshToken
		if len(refreshToken) > 20 {
			refreshToken = refreshToken[:20] + "..." + refreshToken[len(refreshToken)-10:]
		}
		sb.WriteString(fmt.Sprintf("Refresh Token: %s\n\n", refreshToken))
	}

	// Scopes
	if tokenResp.Scope != "" {
		sb.WriteString(fmt.Sprintf("Granted Scopes: %s\n\n", tokenResp.Scope))
	}

	// ID Token Claims
	if claims != nil {
		sb.WriteString("ID Token Claims:\n")
		sb.WriteString(fmt.Sprintf("  Subject (sub): %s\n", claims.Subject))
		sb.WriteString(fmt.Sprintf("  Issuer (iss): %s\n", claims.Issuer))
		sb.WriteString(fmt.Sprintf("  Audience (aud): %s\n", claims.Audience))
		sb.WriteString(fmt.Sprintf("  Issued At (iat): %s\n", formatUnixTime(claims.IssuedAt)))
		sb.WriteString(fmt.Sprintf("  Expiration (exp): %s\n", formatUnixTime(claims.Expiration)))

		// User information
		sb.WriteString("\nUser Information:\n")
		if claims.Name != "" {
			sb.WriteString(fmt.Sprintf("  Name: %s\n", claims.Name))
		}
		if claims.Email != "" {
			sb.WriteString(fmt.Sprintf("  Email: %s\n", claims.Email))
			sb.WriteString(fmt.Sprintf("  Email Verified: %t\n", claims.EmailVerified))
		}
		if claims.Picture != "" {
			sb.WriteString(fmt.Sprintf("  Picture: %s\n", claims.Picture))
		}
		if claims.GivenName != "" {
			sb.WriteString(fmt.Sprintf("  Given Name: %s\n", claims.GivenName))
		}
		if claims.FamilyName != "" {
			sb.WriteString(fmt.Sprintf("  Family Name: %s\n", claims.FamilyName))
		}
		if claims.Locale != "" {
			sb.WriteString(fmt.Sprintf("  Locale: %s\n", claims.Locale))
		}
	}

	return sb.String()
}

// base64URLDecode decodes a base64url encoded string
func base64URLDecode(s string) ([]byte, error) {
	// Add padding if needed
	switch len(s) % 4 {
	case 0:
		// No padding needed
	case 2:
		s += "=="
	case 3:
		s += "="
	default:
		return nil, fmt.Errorf("invalid base64url string length")
	}

	// Replace URL-safe characters
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")

	// Decode
	return base64.StdEncoding.DecodeString(s)
}

// formatUnixTime formats a Unix timestamp as a human-readable time
func formatUnixTime(timestamp int64) string {
	t := time.Unix(timestamp, 0)
	return t.Format(time.RFC3339)
}
