package siwe

import (
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestMessageParserSimple(t *testing.T) {
	text := `test.com wants you to sign in with your Ethereum account:
0xdEADBEeF00000000000000000000000000000000


URI: https://example.com/uri
Version: 1
Chain ID: 12345
Nonce: 12345678
Issued At: 2022-02-15T12:34:56.789Z`

	msg, err := MessageFromString(text)
	assert.Nil(t, err)

	assert.Equal(t, "test.com", msg.Domain)
	assert.Equal(t, "deadbeef00000000000000000000000000000000", hex.EncodeToString(msg.Address.Bytes()))
	assert.Nil(t, msg.Statement)
	assert.Equal(t, "https://example.com/uri", msg.URI)
	assert.Equal(t, V1, msg.Version)
	assert.Equal(t, int64(12345), msg.ChainID)
	assert.Equal(t, "12345678", msg.Nonce)
	assert.Equal(t, time.Date(2022, 2, 15, 12, 34, 56, 789000000, time.UTC), msg.IssuedAt)
	assert.Nil(t, msg.ExpirationTime)
	assert.Nil(t, msg.NotBefore)
	assert.Nil(t, msg.RequestID)
	assert.Equal(t, 0, len(msg.Resources))

	assert.Equal(t, text, msg.String())
}

func TestMessageParserWithOptionals(t *testing.T) {
	text := `test.com wants you to sign in with your Ethereum account:
0xdEADBEeF00000000000000000000000000000000

Statement 123

URI: https://example.com/uri
Version: 1
Chain ID: 12345
Nonce: 12345678
Issued At: 2022-02-15T12:34:56.789Z
Expiration Time: 2022-03-15T12:34:56.789Z
Not Before: 2022-02-15T00:00:00.000Z
Request ID: 123456
Resources:
- ipfs://deadbeef
- https://example.com/claim.json`

	msg, err := MessageFromString(text)
	assert.Nil(t, err)

	assert.Equal(t, "test.com", msg.Domain)
	assert.Equal(t, "deadbeef00000000000000000000000000000000", hex.EncodeToString(msg.Address.Bytes()))
	if assert.NotNil(t, msg.Statement) {
		assert.Equal(t, "Statement 123", *msg.Statement)
	}
	assert.Equal(t, "https://example.com/uri", msg.URI)
	assert.Equal(t, V1, msg.Version)
	assert.Equal(t, int64(12345), msg.ChainID)
	assert.Equal(t, "12345678", msg.Nonce)
	assert.Equal(t, time.Date(2022, 2, 15, 12, 34, 56, 789000000, time.UTC), msg.IssuedAt)
	if assert.NotNil(t, msg.ExpirationTime) {
		assert.Equal(t, time.Date(2022, 3, 15, 12, 34, 56, 789000000, time.UTC), *msg.ExpirationTime)
	}
	if assert.NotNil(t, msg.NotBefore) {
		assert.Equal(t, time.Date(2022, 2, 15, 0, 0, 0, 0, time.UTC), *msg.NotBefore)
	}
	if assert.NotNil(t, msg.RequestID) {
		assert.Equal(t, "123456", *msg.RequestID)
	}
	assert.Equal(t, 2, len(msg.Resources))
	assert.Equal(t, "ipfs://deadbeef", msg.Resources[0])
	assert.Equal(t, "https://example.com/claim.json", msg.Resources[1])

	assert.Equal(t, text, msg.String())
}

func TestMessageVerifySigSimple(t *testing.T) {
	inputJson := `{
	"address" : "0x6Da01670d8fc844e736095918bbE11fE8D564163",
	"chainId" : 1,
	"domain" : "localhost:4361",
	"issuedAt" : "2021-12-07T18:28:18.807Z",
	"nonce" : "kEWepMt9knR6lWJ6A",
	"statement" : "SIWE Notepad Example",
	"uri" : "http://localhost:4361",
	"version" : "1"
	}`

	signature := "6228b3ecd7bf2df018183aeab6b6f1db1e9f4e3cbe24560404112e25363540eb679934908143224d746bbb5e1aa65ab435684081f4dbb74a0fec57f98f40f5051c"

	var msg Message
	err := json.Unmarshal([]byte(inputJson), &msg)
	assert.Nil(t, err)

	sig, err := hex.DecodeString(signature)
	assert.Nil(t, err)

	err = msg.VerifySignature(sig)
	assert.Nil(t, err)

	assert.True(t, msg.Valid())
}

func TestMessageVerifySigWithOptions(t *testing.T) {
	text := `localhost wants you to sign in with your Ethereum account:
0x4b60ffAf6fD681AbcC270Faf4472011A4A14724C

Allow localhost to access your orbit using their temporary session key: did:key:z6Mktud6LcDFb3heS7FFWoJhiCafmUPkCAgpvJLv5E6fgBJg#z6Mktud6LcDFb3heS7FFWoJhiCafmUPkCAgpvJLv5E6fgBJg

URI: did:key:z6Mktud6LcDFb3heS7FFWoJhiCafmUPkCAgpvJLv5E6fgBJg#z6Mktud6LcDFb3heS7FFWoJhiCafmUPkCAgpvJLv5E6fgBJg
Version: 1
Chain ID: 1
Nonce: PPrtjztx2lYqWbqNs
Issued At: 2021-12-20T12:29:25.907Z
Expiration Time: 2021-12-20T12:44:25.906Z
Resources:
- kepler://bafk2bzacecn2cdbtzho72x4c62fcxvcqj23padh47s5jyyrv42mtca3yrhlpa#put
- kepler://bafk2bzacecn2cdbtzho72x4c62fcxvcqj23padh47s5jyyrv42mtca3yrhlpa#del
- kepler://bafk2bzacecn2cdbtzho72x4c62fcxvcqj23padh47s5jyyrv42mtca3yrhlpa#get
- kepler://bafk2bzacecn2cdbtzho72x4c62fcxvcqj23padh47s5jyyrv42mtca3yrhlpa#list`

	signature := "20c0da863b3dbfbb2acc0fb3b9ec6daefa38f3f20c997c283c4818ebeca96878787f84fccc25c4087ccb31ebd782ae1d2f74be076a49c0a8604419e41507e9381c"

	msg, err := MessageFromString(text)
	assert.Nil(t, err)

	sig, err := hex.DecodeString(signature)
	assert.Nil(t, err)

	err = msg.VerifySignature(sig)
	assert.Nil(t, err)

	assert.True(t, msg.ValidAt(time.Date(2021, 12, 20, 12, 44, 25, 0, time.UTC)))
	assert.False(t, msg.ValidAt(time.Date(2021, 12, 20, 12, 44, 26, 0, time.UTC)))

	assert.True(t, msg.ValidAt(time.Date(2021, 12, 20, 4, 44, 25, 0, time.FixedZone("UTC-8", -8*3600))))
	assert.False(t, msg.ValidAt(time.Date(2021, 12, 20, 4, 44, 26, 0, time.FixedZone("UTC-8", -8*3600))))
}

func TestMessageVerifyNoChecksumAddress(t *testing.T) {
	text := `localhost:3000 wants you to sign in with your Ethereum account:
0x85997cf3567563fa62e7a00ba3575a440b5a3b57

Sign in with Ethereum to the Vibe Canvas app.

URI: http://localhost:3000
Version: 1
Chain ID: 1
Nonce: okPqjspj7qmHZ7t4s
Issued At: 2022-06-06T23:42:06.323Z
Expiration Time: 2022-06-06T23:47:06.323Z`

	signature := "81314029c13e009c01760f8cfa769d60b720b778500824eda312c4a05999e642183e314aa5578602e869e3f31c9a13c01be583752294ea572c106002498cf6991b"

	msg, err := MessageFromString(text)
	assert.Nil(t, err)

	sig, err := hex.DecodeString(signature)
	assert.Nil(t, err)

	err = msg.VerifySignature(sig)
	assert.Nil(t, err)
}
