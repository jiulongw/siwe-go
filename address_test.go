package siwe

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseAddress(t *testing.T) {
	var a Address
	var err error

	err = a.Parse(nil)
	assert.NotNil(t, err)

	err = a.Parse([]byte("00"))
	assert.NotNil(t, err)

	err = a.Parse([]byte("0000000000000000000000000000000000000000"))
	assert.Nil(t, err)
	assert.Equal(t, "0x0000000000000000000000000000000000000000", a.String())

	err = a.Parse([]byte("0x0000000000000000000000000000000000000000"))
	assert.Nil(t, err)
	assert.Equal(t, "0x0000000000000000000000000000000000000000", a.String())
}

func TestChecksumString(t *testing.T) {
	var a Address
	var err error

	err = a.ParseString("0xdeadbeef00000000deadbeef00000000deadbeef")
	assert.Nil(t, err)
	assert.Equal(t, "0xdEadBeEf00000000DeADBeef00000000dEAdBeeF", a.String())
}
