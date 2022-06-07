package siwe

import (
	"bufio"
	"errors"
	"io"
	"strconv"
	"strings"
	"time"
)

type parser struct {
	scanner *bufio.Scanner
	msg     *Message
	prev    *string
	err     error
}

func (p *parser) parse() error {
	ok := p.ruleDomain() &&
		p.ruleAddress() &&
		p.ruleEmptyLine() &&
		p.ruleStatement() &&
		p.ruleEmptyLine() &&
		p.ruleURI() &&
		p.ruleVersion() &&
		p.ruleChainID() &&
		p.ruleNonce() &&
		p.ruleIssuedAt() &&
		p.ruleExpirationTime() &&
		p.ruleNotBefore() &&
		p.ruleRequestID() &&
		p.ruleResources()

	if !ok {
		if p.err != nil {
			return p.err
		} else {
			return io.ErrUnexpectedEOF
		}
	}

	return nil
}

func (p *parser) nextLine() (string, bool) {
	if p.err != nil {
		return "", false
	}

	if p.prev != nil {
		l := *p.prev
		p.prev = nil
		return l, true
	}

	if p.scanner.Scan() {
		return p.scanner.Text(), true
	}

	if err := p.scanner.Err(); err != nil {
		p.err = err
	}

	return "", false
}

func (p *parser) optionalRule(rule func(l string) (bool, error)) bool {
	l, ok := p.nextLine()
	if !ok {
		return true
	}

	if ok, err := rule(l); err != nil {
		p.err = err
		return false
	} else if !ok {
		p.prev = &l
	}

	return true
}

func (p *parser) ruleEmptyLine() bool {
	l, ok := p.nextLine()
	if !ok {
		return false
	}

	if l != "" {
		p.err = errors.New("empty line expected")
		return false
	}

	return true
}

func (p *parser) ruleDomain() bool {
	l, ok := p.nextLine()
	if !ok {
		return false
	}

	if !strings.HasSuffix(l, DomainMessage) {
		p.err = errors.New("invalid domain line")
		return false
	}

	d := strings.SplitN(l, " ", 2)[0]
	p.msg.Domain = d
	return true
}

func (p *parser) ruleAddress() bool {
	l, ok := p.nextLine()
	if !ok {
		return false
	}

	err := p.msg.Address.ParseString(l)
	if err != nil {
		p.err = err
		return false
	}

	return true
}

func (p *parser) ruleStatement() bool {
	return p.optionalRule(func(l string) (bool, error) {
		if l == "" {
			return false, nil
		}

		p.msg.Statement = &l
		return true, nil
	})
}

func (p *parser) ruleURI() bool {
	l, ok := p.nextLine()
	if !ok {
		return false
	}

	if !strings.HasPrefix(l, URIPrefix) {
		p.err = errors.New("invalid URI line")
		return false
	}

	p.msg.URI = l[len(URIPrefix):]
	return true
}

func (p *parser) ruleVersion() bool {
	l, ok := p.nextLine()
	if !ok {
		return false
	}

	if !strings.HasPrefix(l, VersionPrefix) {
		p.err = errors.New("invalid Version line")
		return false
	}

	v := l[len(VersionPrefix):]
	if v != string(V1) {
		p.err = errors.New("version not supported")
		return false
	}

	p.msg.Version = V1
	return true
}

func (p *parser) ruleChainID() bool {
	l, ok := p.nextLine()
	if !ok {
		return false
	}

	if !strings.HasPrefix(l, ChainIDPrefix) {
		p.err = errors.New("invalid ChainID line")
		return false
	}

	id, err := strconv.ParseInt(l[len(ChainIDPrefix):], 10, 64)
	if err != nil {
		p.err = err
		return false
	}

	p.msg.ChainID = id
	return true
}

func (p *parser) ruleNonce() bool {
	l, ok := p.nextLine()
	if !ok {
		return false
	}

	if !strings.HasPrefix(l, NoncePrefix) {
		p.err = errors.New("invalid Nonce line")
		return false
	}

	p.msg.Nonce = l[len(NoncePrefix):]
	return true
}

func (p *parser) ruleIssuedAt() bool {
	l, ok := p.nextLine()
	if !ok {
		return false
	}

	if !strings.HasPrefix(l, IssuedAtPrefix) {
		p.err = errors.New("invalid IssuedAt line")
		return false
	}

	v, err := time.Parse(TimeLayout, l[len(IssuedAtPrefix):])
	if err != nil {
		p.err = err
		return false
	}

	p.msg.IssuedAt = v
	return true
}

func (p *parser) ruleExpirationTime() bool {
	return p.optionalRule(func(l string) (bool, error) {
		if !strings.HasPrefix(l, ExpirationTimePrefix) {
			return false, nil
		}

		v, err := time.Parse(TimeLayout, l[len(ExpirationTimePrefix):])
		if err != nil {
			return false, err
		}

		p.msg.ExpirationTime = &v
		return true, nil
	})
}

func (p *parser) ruleNotBefore() bool {
	return p.optionalRule(func(l string) (bool, error) {
		if !strings.HasPrefix(l, NotBeforePrefix) {
			return false, nil
		}

		v, err := time.Parse(TimeLayout, l[len(NotBeforePrefix):])
		if err != nil {
			return false, err
		}

		p.msg.NotBefore = &v
		return true, nil
	})
}

func (p *parser) ruleRequestID() bool {
	return p.optionalRule(func(l string) (bool, error) {
		if !strings.HasPrefix(l, RequestIDPrefix) {
			return false, nil
		}

		id := l[len(RequestIDPrefix):]
		p.msg.RequestID = &id
		return true, nil
	})
}

func (p *parser) ruleResources() bool {
	return p.optionalRule(func(l string) (bool, error) {
		if !strings.HasPrefix(l, ResourcesPrefix) {
			return false, nil
		}

		for p.ruleResource() {
		}

		return true, nil
	})
}

func (p *parser) ruleResource() bool {
	l, ok := p.nextLine()
	if !ok {
		return false
	}

	if !strings.HasPrefix(l, ResourcePrefix) {
		return false
	}

	p.msg.Resources = append(p.msg.Resources, l[len(ResourcePrefix):])
	return true
}
