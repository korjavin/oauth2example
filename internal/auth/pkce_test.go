package auth

import (
	"testing"
)

func TestGenerateCodeVerifier(t *testing.T) {
	// Generate a code verifier
	verifier, err := GenerateCodeVerifier()
	if err != nil {
		t.Fatalf("Failed to generate code verifier: %v", err)
	}

	// Check that the verifier is not empty
	if verifier == "" {
		t.Error("Generated code verifier is empty")
	}

	// Check that the verifier is the correct length
	// Base64 encoding of 32 bytes should be around 43 characters
	if len(verifier) < 43 || len(verifier) > 128 {
		t.Errorf("Code verifier length is outside the valid range: got %d, want 43-128", len(verifier))
	}

	// Generate another verifier to ensure they're different
	anotherVerifier, err := GenerateCodeVerifier()
	if err != nil {
		t.Fatalf("Failed to generate second code verifier: %v", err)
	}

	// Check that the verifiers are different
	if verifier == anotherVerifier {
		t.Error("Generated code verifiers should be different")
	}
}

func TestCreateCodeChallenge(t *testing.T) {
	// Generate a code verifier
	verifier, err := GenerateCodeVerifier()
	if err != nil {
		t.Fatalf("Failed to generate code verifier: %v", err)
	}

	// Create a code challenge
	challenge := verifier.CreateCodeChallenge()

	// Check that the challenge is not empty
	if challenge == "" {
		t.Error("Generated code challenge is empty")
	}

	// Create another challenge from the same verifier
	anotherChallenge := verifier.CreateCodeChallenge()

	// Check that the challenges are the same
	if challenge != anotherChallenge {
		t.Error("Code challenges from the same verifier should be identical")
	}
}

func TestVerifyCodeChallenge(t *testing.T) {
	// Generate a code verifier
	verifier, err := GenerateCodeVerifier()
	if err != nil {
		t.Fatalf("Failed to generate code verifier: %v", err)
	}

	// Create a code challenge
	challenge := verifier.CreateCodeChallenge()

	// Verify the challenge
	if !VerifyCodeChallenge(verifier, challenge) {
		t.Error("Code challenge verification failed")
	}

	// Generate another verifier
	anotherVerifier, err := GenerateCodeVerifier()
	if err != nil {
		t.Fatalf("Failed to generate second code verifier: %v", err)
	}

	// Verify with the wrong verifier
	if VerifyCodeChallenge(anotherVerifier, challenge) {
		t.Error("Code challenge verification should fail with different verifier")
	}
}

func TestCodeVerifierString(t *testing.T) {
	// Generate a code verifier
	verifier, err := GenerateCodeVerifier()
	if err != nil {
		t.Fatalf("Failed to generate code verifier: %v", err)
	}

	// Check that the string representation is correct
	if verifier.String() != string(verifier) {
		t.Errorf("String representation is incorrect: got %s, want %s", verifier.String(), string(verifier))
	}
}

func TestCodeChallengeString(t *testing.T) {
	// Generate a code verifier
	verifier, err := GenerateCodeVerifier()
	if err != nil {
		t.Fatalf("Failed to generate code verifier: %v", err)
	}

	// Create a code challenge
	challenge := verifier.CreateCodeChallenge()

	// Check that the string representation is correct
	if challenge.String() != string(challenge) {
		t.Errorf("String representation is incorrect: got %s, want %s", challenge.String(), string(challenge))
	}
}
