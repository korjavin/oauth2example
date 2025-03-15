package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/korjavin/oauth2example/internal/logger"
)

const (
	// GoogleAuthURL is the Google OAuth2 authorization endpoint
	GoogleAuthURL = "https://accounts.google.com/o/oauth2/v2/auth"

	// GoogleTokenURL is the Google OAuth2 token endpoint
	GoogleTokenURL = "https://oauth2.googleapis.com/token"

	// DefaultTimeout is the default timeout for HTTP requests
	DefaultTimeout = 30 * time.Second
)

// OAuth2Config contains the configuration for the OAuth2 client
type OAuth2Config struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
	Scopes       []string
	Audience     string
}

// TokenResponse represents the response from the token endpoint
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// OAuth2Client handles the OAuth2 authorization flow
type OAuth2Client struct {
	config     OAuth2Config
	httpClient *http.Client
	verifier   PKCECodeVerifier
	challenge  PKCECodeChallenge
	state      string
}

// NewOAuth2Client creates a new OAuth2 client
func NewOAuth2Client(config OAuth2Config) (*OAuth2Client, error) {
	// Generate PKCE code verifier and challenge
	verifier, err := GenerateCodeVerifier()
	if err != nil {
		return nil, fmt.Errorf("failed to generate PKCE code verifier: %w", err)
	}

	challenge := verifier.CreateCodeChallenge()

	// Generate random state parameter
	stateBytes := make([]byte, 16)
	if _, err := rand.Read(stateBytes); err != nil {
		return nil, fmt.Errorf("failed to generate state parameter: %w", err)
	}
	state := base64.URLEncoding.EncodeToString(stateBytes)

	return &OAuth2Client{
		config: config,
		httpClient: &http.Client{
			Timeout: DefaultTimeout,
		},
		verifier:  verifier,
		challenge: challenge,
		state:     state,
	}, nil
}

// GetAuthorizationURL returns the URL to redirect the user to for authorization
func (c *OAuth2Client) GetAuthorizationURL() string {
	logger.Step(1, "Generate Authorization URL",
		"Creating the URL that the user will visit to authenticate and authorize the application")

	// Build the authorization URL
	u, err := url.Parse(GoogleAuthURL)
	if err != nil {
		logger.Error("Failed to parse Google auth URL: %v", err)
		return ""
	}

	// Add query parameters
	q := u.Query()
	q.Set("client_id", c.config.ClientID)
	q.Set("redirect_uri", c.config.RedirectURI)
	q.Set("response_type", "code")
	q.Set("scope", strings.Join(c.config.Scopes, " "))
	q.Set("state", c.state)
	q.Set("code_challenge", string(c.challenge))
	q.Set("code_challenge_method", "S256")

	// Add audience if specified
	if c.config.Audience != "" {
		q.Set("audience", c.config.Audience)
	}

	u.RawQuery = q.Encode()

	authURL := u.String()

	logger.Educational("Authorization URL",
		"The authorization URL contains several important parameters:\n\n"+
			"- client_id: Identifies your application to the OAuth2 provider\n"+
			"- redirect_uri: Where the provider will send the user after authorization\n"+
			"- response_type: 'code' indicates we're using the authorization code flow\n"+
			"- scope: The permissions your application is requesting\n"+
			"- state: A random value to prevent CSRF attacks\n"+
			"- code_challenge: The PKCE code challenge derived from the code verifier\n"+
			"- code_challenge_method: The method used to create the code challenge (S256)\n"+
			"- audience (optional): The intended recipient of the token (for JWT tokens)")

	logger.Debug("Authorization URL: %s", authURL)

	return authURL
}

// ExchangeCodeForToken exchanges the authorization code for tokens
func (c *OAuth2Client) ExchangeCodeForToken(ctx context.Context, code string) (*TokenResponse, error) {
	logger.Step(7, "Exchange Code for Token",
		"Exchanging the authorization code for access and ID tokens")

	// Verify that the code is not empty
	if code == "" {
		return nil, fmt.Errorf("authorization code is empty")
	}

	// Prepare the token request
	data := url.Values{}
	data.Set("client_id", c.config.ClientID)
	data.Set("client_secret", c.config.ClientSecret)
	data.Set("code", code)
	data.Set("code_verifier", string(c.verifier))
	data.Set("grant_type", "authorization_code")
	data.Set("redirect_uri", c.config.RedirectURI)

	logger.Educational("Token Exchange",
		"The token exchange request includes:\n\n"+
			"- client_id: Identifies your application\n"+
			"- client_secret: Authenticates your application to the OAuth2 provider\n"+
			"- code: The authorization code received from the provider\n"+
			"- code_verifier: The original PKCE verifier that corresponds to the challenge\n"+
			"- grant_type: 'authorization_code' indicates we're exchanging a code for tokens\n"+
			"- redirect_uri: Must match the redirect URI used in the authorization request")

	// Create the HTTP request
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		GoogleTokenURL,
		strings.NewReader(data.Encode()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	// Send the request
	logger.Debug("Sending token request to %s", GoogleTokenURL)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read token response: %w", err)
	}

	// Check for error response
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, body)
	}

	// Parse the response
	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	logger.Step(8, "Tokens Received",
		"Successfully received tokens from the OAuth2 provider")

	logger.Educational("OAuth2 Tokens",
		"The OAuth2 provider returns several tokens:\n\n"+
			"- access_token: Used to access protected resources on behalf of the user\n"+
			"- token_type: Usually 'Bearer', indicates how to use the access token\n"+
			"- expires_in: The lifetime of the access token in seconds\n"+
			"- refresh_token: Used to obtain new access tokens when they expire\n"+
			"- id_token: A JWT containing claims about the user (OpenID Connect)\n"+
			"- scope: The scopes that were actually granted (may differ from requested)")

	return &tokenResp, nil
}

// VerifyState verifies that the state parameter matches
func (c *OAuth2Client) VerifyState(state string) bool {
	if state == "" || c.state == "" {
		return false
	}
	return state == c.state
}

// GetCodeVerifier returns the PKCE code verifier
func (c *OAuth2Client) GetCodeVerifier() string {
	return string(c.verifier)
}

// GetCodeChallenge returns the PKCE code challenge
func (c *OAuth2Client) GetCodeChallenge() string {
	return string(c.challenge)
}
