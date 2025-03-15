package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/korjavin/oauth2example/internal/logger"
)

// CallbackServer is a local HTTP server that receives the OAuth2 callback
type CallbackServer struct {
	server     *http.Server
	port       int
	path       string
	codeChan   chan string
	errChan    chan error
	once       sync.Once
	shutdownWg sync.WaitGroup
}

// NewCallbackServer creates a new callback server
func NewCallbackServer(port int, path string) *CallbackServer {
	return &CallbackServer{
		port:     port,
		path:     path,
		codeChan: make(chan string, 1),
		errChan:  make(chan error, 1),
	}
}

// Start starts the callback server
func (s *CallbackServer) Start() error {
	addr := fmt.Sprintf(":%d", s.port)

	// Create a new HTTP server
	mux := http.NewServeMux()
	mux.HandleFunc(s.path, s.handleCallback)

	s.server = &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	// Check if the port is available
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("port %d is not available: %w", s.port, err)
	}

	logger.Step(3, "Starting Local Callback Server",
		fmt.Sprintf("Starting server on http://localhost:%d%s to receive the authorization code",
			s.port, s.path))

	logger.Educational("Callback Server",
		"The callback server is a local HTTP server that receives the authorization code\n"+
			"from the OAuth2 provider after the user has authenticated and authorized the application.\n"+
			"This is a crucial part of the OAuth2 flow, as it allows the application to securely\n"+
			"receive the authorization code without requiring the user to manually copy and paste it.")

	s.shutdownWg.Add(1)
	go func() {
		defer s.shutdownWg.Done()

		// Start the server
		logger.Debug("Callback server listening on %s", addr)
		if err := s.server.Serve(listener); err != nil && err != http.ErrServerClosed {
			s.errChan <- fmt.Errorf("callback server error: %w", err)
		}
	}()

	return nil
}

// WaitForCode waits for the authorization code to be received
func (s *CallbackServer) WaitForCode(ctx context.Context) (string, error) {
	select {
	case code := <-s.codeChan:
		return code, nil
	case err := <-s.errChan:
		return "", err
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// Stop stops the callback server
func (s *CallbackServer) Stop() {
	s.once.Do(func() {
		logger.Debug("Stopping callback server")

		// Create a context with a timeout for shutdown
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// Shutdown the server
		if err := s.server.Shutdown(ctx); err != nil {
			logger.Error("Error shutting down callback server: %v", err)
		}

		// Wait for the server to finish
		s.shutdownWg.Wait()
		logger.Debug("Callback server stopped")
	})
}

// GetRedirectURI returns the full redirect URI for this callback server
func (s *CallbackServer) GetRedirectURI() string {
	return fmt.Sprintf("http://localhost:%d%s", s.port, s.path)
}

// handleCallback handles the OAuth2 callback request
func (s *CallbackServer) handleCallback(w http.ResponseWriter, r *http.Request) {
	logger.Debug("Received callback request: %s", r.URL.String())

	// Extract the authorization code from the request
	code := r.URL.Query().Get("code")
	if code == "" {
		logger.Error("No authorization code received")
		http.Error(w, "No authorization code received", http.StatusBadRequest)
		s.errChan <- fmt.Errorf("no authorization code received")
		return
	}

	// Extract error if present
	if errMsg := r.URL.Query().Get("error"); errMsg != "" {
		errDesc := r.URL.Query().Get("error_description")
		logger.Error("OAuth error: %s - %s", errMsg, errDesc)
		http.Error(w, fmt.Sprintf("OAuth error: %s - %s", errMsg, errDesc), http.StatusBadRequest)
		s.errChan <- fmt.Errorf("oauth error: %s - %s", errMsg, errDesc)
		return
	}

	// Send the code to the channel
	logger.Step(6, "Authorization Code Received",
		"Received authorization code from the OAuth2 provider")

	logger.Educational("Authorization Code",
		"The authorization code is a temporary code that the OAuth2 provider issues after\n"+
			"the user has authenticated and authorized the application. This code is then exchanged\n"+
			"for an access token, which can be used to access the user's resources.\n\n"+
			"The authorization code is short-lived and can only be used once. This is a security\n"+
			"feature to prevent replay attacks.")

	s.codeChan <- code

	// Display a success page to the user
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)

	successHTML := `
<!DOCTYPE html>
<html>
<head>
    <title>OAuth2 Authorization Successful</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
            text-align: center;
        }
        .success {
            color: #4CAF50;
            font-size: 24px;
            margin-bottom: 20px;
        }
        .info {
            color: #555;
            margin-bottom: 20px;
        }
        .code {
            background-color: #f5f5f5;
            padding: 10px;
            border-radius: 4px;
            font-family: monospace;
            word-break: break-all;
        }
    </style>
</head>
<body>
    <h1 class="success">Authorization Successful!</h1>
    <p class="info">You have successfully authorized the application. You can now close this window and return to the application.</p>
    <div class="code">
        <p>Authorization Code:</p>
        <code>%s</code>
    </div>
</body>
</html>
`
	fmt.Fprintf(w, successHTML, code)
}
