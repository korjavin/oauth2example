# OAuth2 PKCE CLI Example

This CLI application demonstrates the OAuth2 Authorization Code Flow with PKCE (Proof Key for Code Exchange) using Google as the identity provider. It's designed to be educational, with detailed logging that explains each step of the process.

## What is OAuth2 with PKCE?

OAuth2 is an authorization framework that enables third-party applications to obtain limited access to a user's account on an HTTP service. The Authorization Code Flow with PKCE is an extension to the standard OAuth2 Authorization Code Flow, designed to provide additional security for public clients that cannot securely store a client secret.

PKCE (Proof Key for Code Exchange) prevents authorization code interception attacks by using a dynamically created cryptographic challenge. This is particularly important for:
- Mobile applications
- Single-page applications
- Desktop applications
- CLI applications

## How the Flow Works

1. **Generate PKCE Code Verifier and Challenge**
   - The application generates a random code verifier
   - It creates a code challenge by hashing the verifier with SHA256 and base64url encoding it

2. **Authorization Request**
   - The application redirects the user to the authorization server (Google)
   - The request includes the code challenge and other parameters

3. **User Authentication and Consent**
   - The user authenticates with their credentials
   - The user approves the requested scopes

4. **Authorization Code Grant**
   - The authorization server redirects back to the application with an authorization code

5. **Token Exchange**
   - The application exchanges the authorization code and the original code verifier for tokens
   - The authorization server verifies that the code verifier matches the challenge

6. **Token Usage**
   - The application can use the access token to make API requests
   - The ID token contains claims about the user's identity

## Features

- Full implementation of OAuth2 Authorization Code Flow with PKCE
- Google authentication
- Local callback server to receive the authorization code
- Detailed educational logging explaining each step
- Minimal dependencies (mostly standard library)
- Support for profile and email scopes
- Token validation and parsing

## Prerequisites

- Go 1.18 or higher
- A Google Cloud Platform account
- OAuth2 client credentials from Google

## Setup

### 1. Create OAuth2 Credentials in Google Cloud Console

1. Go to the [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Navigate to "APIs & Services" > "Credentials"
4. Click "Create Credentials" > "OAuth client ID"
5. Select "Desktop app" as the application type
6. Enter a name for your OAuth client
7. Add `http://localhost:8080/oauth/callback` to the authorized redirect URIs
8. Click "Create"
9. Note your Client ID and Client Secret

### 2. Set Environment Variables

```bash
export GOOGLE_CLIENT_ID=your-client-id
export GOOGLE_CLIENT_SECRET=your-client-secret
```

Optional environment variables:
```bash
export REDIRECT_URI=http://localhost:8080/oauth/callback  # Default
export DEBUG=true  # Default
```

## Building and Running

### Build the application

```bash
go build -o oauth2cli ./cmd/oauth2cli
```

### Run the application

```bash
./oauth2cli
```

Command-line flags:
- `--port`: Port for the callback server (default: 8080)
- `--callback-path`: Path for the callback endpoint (default: /oauth/callback)
- `--timeout`: Timeout for the authorization flow (default: 5m)
- `--debug`: Enable debug logging
- `--help`: Show help

## How It Works

When you run the application:

1. It generates a PKCE code verifier and challenge
2. Starts a local HTTP server on port 8080 to receive the callback
3. Opens your default browser to the Google authorization page
4. After you authenticate and authorize, Google redirects back to the local server
5. The application exchanges the authorization code for tokens
6. It displays the token information and user claims

## Security Considerations

- The PKCE extension provides protection against authorization code interception
- The state parameter helps prevent cross-site request forgery (CSRF) attacks
- Access tokens should be kept secure and not exposed to third parties
- This example application does not persist tokens; in a real application, you would need to securely store them

## Project Structure

```
oauth2example/
├── cmd/
│   └── oauth2cli/
│       └── main.go         # Main entry point
├── internal/
│   ├── auth/
│   │   ├── oauth2.go       # OAuth2 client implementation
│   │   ├── pkce.go         # PKCE implementation
│   │   └── token.go        # Token handling
│   ├── server/
│   │   └── callback.go     # Local callback server
│   └── logger/
│       └── logger.go       # Custom logger for educational output
├── pkg/
│   └── utils/
│       └── utils.go        # Utility functions
├── go.mod
├── go.sum
└── README.md
```

## Further Reading

- [OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749)
- [OAuth 2.0 for Native Apps](https://tools.ietf.org/html/rfc8252)
- [Proof Key for Code Exchange (PKCE)](https://tools.ietf.org/html/rfc7636)
- [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)
- [Google OAuth 2.0 Documentation](https://developers.google.com/identity/protocols/oauth2)

