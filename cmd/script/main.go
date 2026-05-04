package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"auth-service/pkg/keygenerator"
)

const (
	outputEnv  = "env"
	outputJSON = "json"
	outputText = "text"
)

func main() {
	format := flag.String("format", outputEnv, "output format: env, json, or text")
	privateVar := flag.String("private-var", "PASETO_V4_PRIVATE_KEY", "env var name for the private key")
	publicVar := flag.String("public-var", "PASETO_V4_PUBLIC_KEY", "env var name for the public key")
	flag.Parse()

	pair, err := keygenerator.New().Generate(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "generate paseto keypair: %v\n", err)
		os.Exit(1)
	}

	switch strings.ToLower(strings.TrimSpace(*format)) {
	case outputJSON:
		payload := map[string]string{
			"private_key_base64": pair.PrivateKeyBase64,
			"public_key_base64":  pair.PublicKeyBase64,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(payload); err != nil {
			fmt.Fprintf(os.Stderr, "write json: %v\n", err)
			os.Exit(1)
		}
	case outputText:
		fmt.Printf("private_key_base64: %s\n", pair.PrivateKeyBase64)
		fmt.Printf("public_key_base64: %s\n", pair.PublicKeyBase64)
	case outputEnv:
		fmt.Printf("%s=%s\n", strings.TrimSpace(*privateVar), pair.PrivateKeyBase64)
		fmt.Printf("%s=%s\n", strings.TrimSpace(*publicVar), pair.PublicKeyBase64)
	default:
		fmt.Fprintf(os.Stderr, "unknown format %q\n", *format)
		os.Exit(1)
	}
}
