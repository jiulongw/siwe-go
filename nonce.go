package siwe

import (
	crand "crypto/rand"
	"encoding/binary"
	"math/rand"
	"time"
)

const (
	Alphanumeric = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	nonceSize = 8
)

func init() {
	var b [8]byte
	_, err := crand.Read(b[:])
	if err != nil {
		rand.Seed(time.Now().UnixNano())
	} else {
		rand.Seed(int64(binary.LittleEndian.Uint64(b[:])))
	}
}

func GenerateNonce() string {
	var b [nonceSize]byte
	for i := 0; i < nonceSize; i++ {
		j := rand.Int63n(int64(len(Alphanumeric)))
		b[i] = Alphanumeric[j]
	}

	return string(b[:])
}
