package utils

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// OpenBrowser opens the specified URL in the default browser
func OpenBrowser(url string) error {
	var err error

	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		err = fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}

	if err != nil {
		return fmt.Errorf("failed to open browser: %w", err)
	}

	return nil
}

// GetEnv gets an environment variable with a default value
func GetEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

// GetRequiredEnv gets a required environment variable
// Returns an error if the variable is not set
func GetRequiredEnv(key string) (string, error) {
	value := os.Getenv(key)
	if value == "" {
		return "", fmt.Errorf("required environment variable %s is not set", key)
	}
	return value, nil
}

// GetEnvBool gets a boolean environment variable
// Returns true if the value is "1", "true", "yes", or "y" (case-insensitive)
func GetEnvBool(key string, defaultValue bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}

	value = strings.ToLower(value)
	return value == "1" || value == "true" || value == "yes" || value == "y"
}

// PrintEnvHelp prints help information about required environment variables
func PrintEnvHelp() {
	fmt.Println("Required Environment Variables:")
	fmt.Println("  GOOGLE_CLIENT_ID     - OAuth2 client ID from Google")
	fmt.Println("  GOOGLE_CLIENT_SECRET - OAuth2 client secret from Google")
	fmt.Println("")
	fmt.Println("Optional Environment Variables:")
	fmt.Println("  REDIRECT_URI - Callback URL (default: http://localhost:8080/oauth/callback)")
	fmt.Println("  DEBUG        - Enable/disable detailed logs (default: true)")
	fmt.Println("")
	fmt.Println("Example:")
	fmt.Println("  export GOOGLE_CLIENT_ID=your-client-id")
	fmt.Println("  export GOOGLE_CLIENT_SECRET=your-client-secret")
	fmt.Println("  ./oauth2cli")
}

// FormatCodeBlock formats a string as a code block for display
func FormatCodeBlock(s string) string {
	return fmt.Sprintf("\n```\n%s\n```\n", s)
}

// TruncateString truncates a string to the specified length
// and adds an ellipsis if truncated
func TruncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}

	return s[:maxLen-3] + "..."
}
