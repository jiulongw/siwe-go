# Sign-In with Ethereum

This go module provides a pure Go implementation of EIP-4361: Sign In With Ethereum.

## Installation

```sh
go get github.com/jiulongw/siwe-go
```

## Usage

SIWE exposes a `Message` struct which implements EIP-4361.

### Parsing a SIWE Message

Parsing is done via the `MessageFromString` function:

```go
msg, err := MessageFromString(text_representation)
```

### Verifying and Authenticating a SIWE Message

Verification and Authentication is performed via EIP-191. `VerifySignature` function of `Message` will recover
signature to Ethereum public key and compare it with `Address` field of `Message`.  If either public key
recovery failed, or the recovered public key does not match `Address`, error is returned.

```go
err := msg.VerifySignature(sig)
if err != nil {
  // signature validation failed.
}
```

The time constraints (expiry and not-before) can also be validated, at current or particular times:

```go
if msg.Valid() { ... }
if msg.ValidAt(time.Now()) { ... }
```

Combined verification of time constraints and authentication can be done in a single call with `verify`:

```go
err := msg.Verify(sig)
if err != nil {
  // signature validation failed or time constraints are not satisfied.
}
```

### Serialization of a SIWE Message

`Message` instances can also be serialized as their EIP-4361 string representations via the `String` function.

```go
fmt.Println(msg.String());
```

As well as in EIP-191 Personal-Signature pre-hash signing input form.

```go
fmt.Println(msg.EIP191String())
```

And directly as the EIP-191 Personal-Signature Hashed signing-input.

```go
hash := msg.EIP191Hash()
```

## Example

Parsing and verifying a `Message` is easy:

```go
var str string  // string representation of message
var sig []byte  // message signature to verify

msg, err := MessageFromString(str)
if err != nil {
    panic(err)
}

if err := msg.Verify(sig); err != nil {
    panic(err)
}

// do application-specific things
```

## Disclaimer 

Our Go library for Sign-In with Ethereum has not yet undergone a formal security 
audit. We welcome continued feedback on the usability, architecture, and security 
of this implementation.

## See Also

- [Sign-In with Ethereum: TypeScript](https://github.com/spruceid/siwe)
- [Example SIWE application: login.xyz](https://login.xyz)
- [EIP-4361 Specification Draft](https://eips.ethereum.org/EIPS/eip-4361)
- [EIP-191 Specification](https://eips.ethereum.org/EIPS/eip-191)
