package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"runtime"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// DecryptStream decrypts a JWE payload using a streaming reader and a cancelable context.
// It returns an io.ReadCloser that yields the decrypted payload.
func DecryptStream(ctx context.Context, jwe *jose.JSONWebEncryption, decrypter interface{}) (io.ReadCloser, error) {
	pr, pw := io.Pipe()

	go func() {
		defer pw.Close()

		// Channel to receive decryption result
		resultChan := make(chan []byte, 1)
		errChan := make(chan error, 1)

		go func() {
			decrypted, err := jwe.Decrypt(decrypter)
			if err != nil {
				errChan <- err
				return
			}
			resultChan <- decrypted
		}()

		var decrypted []byte
		select {
		case <-ctx.Done():
			_ = pw.CloseWithError(ctx.Err())
			return
		case err := <-errChan:
			_ = pw.CloseWithError(err)
			return
		case decrypted = <-resultChan:
		}

		// Write decrypted data to pipe, respecting context cancellation
		chunkSize := 4096
		for i := 0; i < len(decrypted); i += chunkSize {
			end := i + chunkSize
			if end > len(decrypted) {
				end = len(decrypted)
			}

			writeDone := make(chan error, 1)
			go func(chunk []byte) {
				_, err := pw.Write(chunk)
				writeDone <- err
			}(decrypted[i:end])

			select {
			case <-ctx.Done():
				_ = pw.CloseWithError(ctx.Err())
				return
			case err := <-writeDone:
				if err != nil {
					_ = pw.CloseWithError(err)
					return
				}
			}
		}
	}()

	return pr, nil
}

func main() {
	// Generate a test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	// Create an encrypter
	encrypter, err := jose.NewEncrypter(jose.A128GCM, jose.Recipient{Algorithm: jose.RSA_OAEP, Key: &privateKey.PublicKey}, nil)
	if err != nil {
		panic(err)
	}

	// Encrypt a large payload
	largePayload := make([]byte, 10*1024*1024) // 10MB
	_, _ = rand.Read(largePayload)

	object, err := encrypter.Encrypt(largePayload)
	if err != nil {
		panic(err)
	}

	serialized := object.FullSerialize()

	// Parse the JWE
	jwe, err := jose.ParseEncrypted(serialized, []jose.SignatureAlgorithm{jose.SignatureAlgorithm(jose.RSA_OAEP)})
	if err != nil {
		panic(err)
	}

	// Test context cancellation
	ctx, cancel := context.WithCancel(context.Background())
	reader, err := DecryptStream(ctx, jwe, privateKey)
	if err != nil {
		panic(err)
	}

	// Read a small chunk
	buf := make([]byte, 1024)
	_, err = reader.Read(buf)
	if err != nil {
		panic(err)
	}

	// Cancel context mid-stream
	cancel()

	// Verify read returns context error
	_, err = reader.Read(buf)
	if !errors.Is(err, context.Canceled) && !errors.Is(err, io.ErrClosedPipe) {
		fmt.Printf("Expected context canceled or closed pipe error, got: %v\n", err)
	}

	// Wait for goroutines to clean up
	time.Sleep(100 * time.Millisecond)

	// Check for goroutine leaks
	baseline := runtime.NumGoroutine()
	fmt.Printf("Active goroutines after cancellation: %d\n", baseline)
	fmt("Hello, Bounty Hunter!")
}
