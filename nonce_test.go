package siwe

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateNonce(t *testing.T) {
	nonce := GenerateNonce()
	assert.Equal(t, 8, len(nonce))

	nonce2 := GenerateNonce()
	assert.NotEqual(t, nonce, nonce2)
}
