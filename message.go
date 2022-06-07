package siwe

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"
)

type version string

type Message struct {
	Domain         string     `json:"domain"`
	Address        Address    `json:"address"`
	Statement      *string    `json:"statement,omitempty"`
	URI            string     `json:"uri"`
	Version        version    `json:"version"`
	ChainID        int64      `json:"chainId"`
	Nonce          string     `json:"nonce"`
	IssuedAt       time.Time  `json:"issuedAt"`
	ExpirationTime *time.Time `json:"expirationTime,omitempty"`
	NotBefore      *time.Time `json:"notBefore,omitempty"`
	RequestID      *string    `json:"requestId,omitempty"`
	Resources      []string   `json:"resources,omitempty"`
}

const (
	V1 version = "1"

	TimeLayout = "2006-01-02T15:04:05.000Z07:00"

	DomainMessage        = " wants you to sign in with your Ethereum account:"
	URIPrefix            = "URI: "
	VersionPrefix        = "Version: "
	ChainIDPrefix        = "Chain ID: "
	NoncePrefix          = "Nonce: "
	IssuedAtPrefix       = "Issued At: "
	ExpirationTimePrefix = "Expiration Time: "
	NotBeforePrefix      = "Not Before: "
	RequestIDPrefix      = "Request ID: "
	ResourcesPrefix      = "Resources:"
	ResourcePrefix       = "- "
)

func MessageFromString(s string) (*Message, error) {
	r := bytes.NewReader([]byte(s))
	m := &Message{}
	if err := m.Read(r); err != nil {
		return nil, err
	}

	return m, nil
}

func (m *Message) Read(r io.Reader) error {
	p := parser{
		scanner: bufio.NewScanner(r),
		msg:     m,
	}

	return p.parse()
}

func (m *Message) Verify(sig []byte) error {
	if err := m.VerifySignature(sig); err != nil {
		return err
	}

	if !m.Valid() {
		return errors.New("message time constraints not satisfied")
	}

	return nil
}

func (m *Message) VerifySignature(sig []byte) error {
	btcsig := make([]byte, 65)
	btcsig[0] = sig[64]
	copy(btcsig[1:], sig)

	pk, _, err := ecdsa.RecoverCompact(btcsig, m.EIP191Hash())
	if err != nil {
		return err
	}

	pkBytes := pk.SerializeUncompressed()
	hPk := sha3.NewLegacyKeccak256()
	hPk.Write(pkBytes[1:])

	if !bytes.Equal(m.Address.Bytes(), hPk.Sum(nil)[12:]) {
		return errors.New("signature validation failed")
	}

	return nil
}

func (m *Message) Valid() bool {
	return m.ValidAt(time.Now())
}

func (m *Message) ValidAt(t time.Time) bool {
	if m.ExpirationTime != nil && t.After(*m.ExpirationTime) {
		return false
	}

	if m.NotBefore != nil && t.Before(*m.NotBefore) {
		return false
	}

	return true
}

func (m *Message) EIP191String() string {
	msg := m.String()
	return fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(msg), msg)
}

func (m *Message) EIP191Hash() []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write([]byte(m.EIP191String()))
	return h.Sum(nil)
}

func (m *Message) String() string {
	var sb strings.Builder
	sb.WriteString(m.Domain)
	sb.WriteString(DomainMessage)
	sb.WriteByte('\n')

	addr := m.Address.RawString()
	if addr == "" {
		addr = m.Address.String()
	}
	sb.WriteString(addr)
	sb.WriteByte('\n')

	sb.WriteByte('\n')
	if m.Statement != nil {
		sb.WriteString(*m.Statement)
		sb.WriteByte('\n')
	}
	sb.WriteByte('\n')

	sb.WriteString(URIPrefix)
	sb.WriteString(m.URI)
	sb.WriteByte('\n')

	sb.WriteString(VersionPrefix)
	sb.WriteString(string(m.Version))
	sb.WriteByte('\n')

	sb.WriteString(ChainIDPrefix)
	sb.WriteString(strconv.FormatInt(m.ChainID, 10))
	sb.WriteByte('\n')

	sb.WriteString(NoncePrefix)
	sb.WriteString(m.Nonce)
	sb.WriteByte('\n')

	sb.WriteString(IssuedAtPrefix)
	sb.WriteString(m.IssuedAt.Format(TimeLayout))

	if m.ExpirationTime != nil {
		sb.WriteByte('\n')
		sb.WriteString(ExpirationTimePrefix)
		sb.WriteString(m.ExpirationTime.Format(TimeLayout))
	}

	if m.NotBefore != nil {
		sb.WriteByte('\n')
		sb.WriteString(NotBeforePrefix)
		sb.WriteString(m.NotBefore.Format(TimeLayout))
	}

	if m.RequestID != nil {
		sb.WriteByte('\n')
		sb.WriteString(RequestIDPrefix)
		sb.WriteString(*m.RequestID)
	}

	if len(m.Resources) > 0 {
		sb.WriteByte('\n')
		sb.WriteString(ResourcesPrefix)
		for _, r := range m.Resources {
			sb.WriteByte('\n')
			sb.WriteString(ResourcePrefix)
			sb.WriteString(r)
		}
	}

	return sb.String()
}
