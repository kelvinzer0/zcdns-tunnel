package gossip

import (
	"crypto/hmac"
	"crypto/sha256"
)

// SignMessage signs a message with HMAC-SHA256
func SignMessage(message []byte, secret []byte) []byte {
	h := hmac.New(sha256.New, secret)
	h.Write(message)
	return h.Sum(nil)
}

// VerifyMessage verifies a message signature using HMAC-SHA256
func VerifyMessage(message []byte, signature []byte, secret []byte) bool {
	h := hmac.New(sha256.New, secret)
	h.Write(message)
	calculatedSignature := h.Sum(nil)
	return hmac.Equal(calculatedSignature, signature)
}