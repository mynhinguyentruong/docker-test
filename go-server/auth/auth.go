package auth

import (
	"os"

	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"log/slog"
)

func Sign(message []byte) (string, error) {

  privateKey, err := LoadPrivateKeyFromENV()
  if err != nil {
    slog.Debug(fmt.Sprintln(err))
    return "", err
  }

	signedData := ed25519.Sign(privateKey, message)
	signature := base64.StdEncoding.EncodeToString(signedData)

  publicKeyData, err := GetPublicKeyFromPrivateKey(privateKey)
  if err != nil {
    slog.Debug(fmt.Sprintln(err))
  }
  publicKey := base64.StdEncoding.EncodeToString(publicKeyData)


	// signature is <publicKey>:<signature>
  return fmt.Sprintf("%s:%s", publicKey, signature), nil
}

func LoadPrivateKeyFromENV() (ed25519.PrivateKey, error) {
	pemString := os.Getenv("PEM_PRIVATE_KEY")
	if pemString == "" {
		slog.Debug("Failed to get pemString from ENV, have you set up your environment variable?", "line", "22")
		return []byte(pemString), fmt.Errorf("empty PEM_PRIVATE_KEY ENV")
	}

	privateKey, err := ssh.ParseRawPrivateKey([]byte(pemString))
	if err != nil {
		return []byte(""), fmt.Errorf("failed to parse raw private_key from pem string")
	}

	// Type assertion to *ed25519.PrivateKey type
	ed25519PrivateKey, ok := privateKey.(*ed25519.PrivateKey)
	if !ok {
		return []byte(""), fmt.Errorf("failed to assert type into *ed25519.PrivateKey")
	}

	// dereferencing the pointer
	myKey := *ed25519PrivateKey

	return myKey, nil

}

func GetPublicKeyFromPrivateKey(private_key ed25519.PrivateKey) (ed25519.PublicKey, error) {
	cryptoPublicKey := private_key.Public()

	// type assertion
	pubkey, ok := cryptoPublicKey.(ed25519.PublicKey)
	if !ok {
		return []byte(""), errors.New("failed to assert into ed25519.PublicKey type")
	}

	sEnc := base64.StdEncoding.EncodeToString(pubkey)
	fmt.Println("pubkey", sEnc)

	return pubkey, nil
}

