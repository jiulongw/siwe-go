package siwe

import (
	"encoding/hex"
	"errors"

	"golang.org/x/crypto/sha3"
)

type Address [20]byte

func (a *Address) ParseString(s string) error {
	return a.Parse([]byte(s))
}

func (a *Address) Parse(b []byte) error {
	if len(b) == 42 {
		if b[0] != '0' || b[1] != 'x' {
			return errors.New("invalid Address prefix")
		}

		_, err := hex.Decode(a[:], b[2:])
		return err
	} else if len(b) == 40 {
		_, err := hex.Decode(a[:], b)
		return err
	} else {
		return errors.New("invalid Address length")
	}
}

func (a *Address) UnmarshalJSON(b []byte) error {
	if len(b) < 2 || b[0] != '"' || b[len(b)-1] != '"' {
		return errors.New("invalid Address format")
	}

	return a.Parse(b[1 : len(b)-1])
}

func (a *Address) NonCheckSumString() string {
	return "0x" + hex.EncodeToString(a[:])
}

func (a *Address) CheckSumString() string {
	str := []byte(hex.EncodeToString(a[:]))
	h := sha3.NewLegacyKeccak256()
	h.Write(str)
	sum := hex.EncodeToString(h.Sum(nil))

	for i := 0; i < len(str); i++ {
		if sum[i] >= '8' && str[i] >= 'a' && str[i] <= 'f' {
			str[i] = str[i] - 'a' + 'A'
		}
	}

	return "0x" + string(str)
}

func (a *Address) String() string {
	return a.CheckSumString()
}
