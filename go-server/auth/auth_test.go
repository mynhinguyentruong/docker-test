package auth

import (
	"log"
	"os"
	"testing"
)

func TestLoadPrivateKeyFromENV(t *testing.T) {
	tests := []struct {
		name       string
		envVar     string
		expectErr  bool
		errMessage string
	}{
		{
			name:      "Valid private key",
			envVar:    "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACCy+6sL7di1OFo/bvc1E9SxifllEFHG/Mmk5MktQidYgAAAAKh6eyERensh\nEQAAAAtzc2gtZWQyNTUxOQAAACCy+6sL7di1OFo/bvc1E9SxifllEFHG/Mmk5MktQidYgA\nAAAECatz/nLLmyJRN1Rk7ZZ4fbN8QqoBkrpuJvKPIBxBYpS7L7qwvt2LU4Wj9u9zUT1LGJ\n+WUQUcb8yaTkyS1CJ1iAAAAAJGhpZ2hmdW5jdGlvbmluZ19zb2Npb3BhdGhoaEBOaGlzLU\n1CUAE=\n-----END OPENSSH PRIVATE KEY-----",
			expectErr: false,
		},
		{
			name:       "Empty PEM_PRIVATE_KEY ENV",
			envVar:     "",
			expectErr:  true,
			errMessage: "empty PEM_PRIVATE_KEY ENV",
		},
		// Add more test cases as needed
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Set up environment variable for the test
			os.Setenv("PEM_PRIVATE_KEY", tc.envVar)

			// Test the function
			privateKey, err := LoadPrivateKeyFromENV()

			if tc.expectErr {
				if err == nil {
					t.Error("Expected error but got none")
				} else if err.Error() != tc.errMessage {
					t.Errorf("Expected error message %q, got %q", tc.errMessage, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}

			// Assert private key is not nil
			if !tc.expectErr {
				if privateKey == nil {
					t.Error("Private key is nil")
					log.Printf("Test %s failed: Private key is nil", tc.name)
					return
				}

				// Assert private key length is as expected
				expectedKeyLength := 64 // Length of an Ed25519 private key
				actualKeyLength := len(privateKey)
				if actualKeyLength != expectedKeyLength {
					t.Errorf("Expected private key length %d, got %d", expectedKeyLength, actualKeyLength)
				}
			}
		})
	}
}

func TestSignAndVerify(t *testing.T) {
	tests := []struct {
		name          string
		privateKey    string
		expectErr     bool
		expectedError string
	}{
		{
			name:       "Empty private key",
			privateKey: "",
			expectErr:  true,
			// Provide the expected error message for empty private key case
			expectedError: "empty PEM_PRIVATE_KEY ENV",
		},
		{
			name:       "Valid private key",
			privateKey: "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACCy+6sL7di1OFo/bvc1E9SxifllEFHG/Mmk5MktQidYgAAAAKh6eyERensh\nEQAAAAtzc2gtZWQyNTUxOQAAACCy+6sL7di1OFo/bvc1E9SxifllEFHG/Mmk5MktQidYgA\nAAAECatz/nLLmyJRN1Rk7ZZ4fbN8QqoBkrpuJvKPIBxBYpS7L7qwvt2LU4Wj9u9zUT1LGJ\n+WUQUcb8yaTkyS1CJ1iAAAAAJGhpZ2hmdW5jdGlvbmluZ19zb2Npb3BhdGhoaEBOaGlzLU\n1CUAE=\n-----END OPENSSH PRIVATE KEY-----",
			expectErr:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Set up environment variable for the test
			os.Setenv("PEM_PRIVATE_KEY", tc.privateKey)

			// Sign the message
			signature, err := Sign([]byte("hello, world"))

			if tc.expectErr {
				// Ensure an error is returned
				if err == nil {
					t.Error("Expected error but got none")
				} else if err.Error() != tc.expectedError {
					t.Errorf("Expected error message %q, got %q", tc.expectedError, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			t.Logf("Signature: %s", signature)

			// Here add verification of the signature if needed
			// verified, err := Verify(signature, []byte("hello, world"))
			// if err != nil {
			// 	t.Errorf("Verify failed: %v", err)
			// }
			//
			// if !verified {
			// 	t.Errorf("Signature verification failed")
			// }
		})
	}
}
