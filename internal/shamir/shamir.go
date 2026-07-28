// Package shamir splits a secret into shares, any threshold of which can
// reconstruct it.
//
// Deadhand uses this for guardian release: the content key is split among N
// guardians, and K of them together can open the payload. No single guardian
// can, and neither can the server — it only ever holds shares it cannot
// combine, because it does not hold enough of them.
//
// This is Shamir's scheme over GF(2^8), the same construction Vault and
// ssss use: each byte of the secret gets its own random polynomial of degree
// K-1, evaluated at each share's x coordinate. Recovering it is Lagrange
// interpolation at x=0.
//
// Implemented here rather than pulled in because the whole thing is 150 lines
// of finite-field arithmetic, and a dependency for that would be harder to
// audit than the code itself. It is checked against the properties that matter:
// K-1 shares reveal nothing, K shares always reconstruct, and every subset of
// size K agrees.
package shamir

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
)

// Limits on the scheme. The x coordinate is one byte and zero is reserved for
// the secret itself, so 255 shares is the ceiling.
const (
	MinParts     = 2
	MaxParts     = 255
	MinThreshold = 2
)

var (
	// ErrBadParameters is returned for a nonsensical threshold or share count.
	ErrBadParameters = errors.New("shamir: invalid threshold or share count")
	// ErrTooFewShares is returned when fewer shares than the threshold are
	// supplied. It cannot say what the threshold *was* — that is not
	// recoverable from the shares themselves.
	ErrTooFewShares = errors.New("shamir: not enough shares to reconstruct")
	// ErrMalformedShare is returned for a share of the wrong shape.
	ErrMalformedShare = errors.New("shamir: malformed share")
	// ErrInconsistentShares is returned when shares have differing lengths or
	// duplicate x coordinates.
	ErrInconsistentShares = errors.New("shamir: shares do not belong together")
)

/* --------------------------------------------------------- GF(2^8) ------- */

// Exponential and logarithm tables for the field, generated once at init using
// the standard AES polynomial 0x11b with generator 3.
var (
	expTable [256]byte
	logTable [256]byte
)

func init() {
	x := byte(1)
	for i := 0; i < 255; i++ {
		expTable[i] = x
		logTable[x] = byte(i)
		// Multiply by the generator, 3 = x + 1.
		x = mulNoTable(x, 3)
	}
	expTable[255] = expTable[0]
}

// mulNoTable multiplies in GF(2^8) the long way. Used only to build the
// tables, since it is not constant time.
func mulNoTable(a, b byte) byte {
	var p byte
	for i := 0; i < 8; i++ {
		if b&1 != 0 {
			p ^= a
		}
		high := a & 0x80
		a <<= 1
		if high != 0 {
			a ^= 0x1b
		}
		b >>= 1
	}
	return p
}

// add in GF(2^8) is XOR. Subtraction is the same operation.
func add(a, b byte) byte { return a ^ b }

// mul multiplies two field elements.
//
// The zero cases are folded in with a constant-time select rather than an
// early return, so the timing does not reveal whether a coefficient was zero.
func mul(a, b byte) byte {
	sum := int(logTable[a]) + int(logTable[b])
	if sum >= 255 {
		sum -= 255
	}
	result := expTable[sum]

	// Both branches are already byte-valued — 0, or an entry from expTable —
	// so the conversion cannot overflow. gosec cannot see that through
	// ConstantTimeSelect's int signature.
	zero := subtle.ConstantTimeByteEq(a, 0) | subtle.ConstantTimeByteEq(b, 0)
	return byte(subtle.ConstantTimeSelect(zero, 0, int(result))) //nolint:gosec // G115: both branches are byte-ranged
}

// div divides a by b. b must not be zero.
func div(a, b byte) (byte, error) {
	if b == 0 {
		return 0, errors.New("shamir: division by zero")
	}
	if a == 0 {
		return 0, nil
	}
	diff := int(logTable[a]) - int(logTable[b])
	if diff < 0 {
		diff += 255
	}
	return expTable[diff], nil
}

/* ----------------------------------------------------------- shares ------ */

// Share is one participant's piece. The final byte is the x coordinate; the
// preceding bytes are the polynomial evaluations for each secret byte.
type Share []byte

// X returns the share's coordinate, which identifies it.
func (s Share) X() (byte, error) {
	if len(s) < 2 {
		return 0, ErrMalformedShare
	}
	return s[len(s)-1], nil
}

// Split divides secret into parts shares, of which threshold are needed.
func Split(secret []byte, parts, threshold int) ([]Share, error) {
	if len(secret) == 0 {
		return nil, errors.New("shamir: nothing to split")
	}
	if parts < MinParts || parts > MaxParts {
		return nil, fmt.Errorf("%w: parts must be between %d and %d, got %d",
			ErrBadParameters, MinParts, MaxParts, parts)
	}
	if threshold < MinThreshold || threshold > parts {
		return nil, fmt.Errorf("%w: threshold must be between %d and parts (%d), got %d",
			ErrBadParameters, MinThreshold, parts, threshold)
	}

	// Distinct non-zero x coordinates. x=0 evaluates to the secret itself, so
	// handing it out as a share would hand out the secret.
	xs := make([]byte, parts)
	for i := 0; i < parts; i++ {
		xs[i] = byte(i + 1)
	}

	shares := make([]Share, parts)
	for i := range shares {
		shares[i] = make(Share, len(secret)+1)
		shares[i][len(secret)] = xs[i]
	}

	for byteIndex, value := range secret {
		coefficients, err := randomPolynomial(value, threshold-1)
		if err != nil {
			return nil, err
		}
		for i, x := range xs {
			shares[i][byteIndex] = evaluate(coefficients, x)
		}
	}
	return shares, nil
}

// Combine reconstructs the secret from a set of shares.
//
// It cannot verify that the shares are the right ones: Shamir provides no
// integrity, so a wrong-but-well-formed share yields wrong-but-well-formed
// output. Callers must authenticate the result — Deadhand does, because the
// recovered value is an AEAD key and decryption fails loudly if it is wrong.
func Combine(shares []Share) ([]byte, error) {
	if len(shares) < MinThreshold {
		return nil, fmt.Errorf("%w: got %d", ErrTooFewShares, len(shares))
	}

	size := len(shares[0])
	if size < 2 {
		return nil, ErrMalformedShare
	}

	seen := make(map[byte]bool, len(shares))
	xs := make([]byte, len(shares))
	for i, s := range shares {
		if len(s) != size {
			return nil, fmt.Errorf("%w: differing lengths", ErrInconsistentShares)
		}
		x := s[size-1]
		if x == 0 {
			return nil, fmt.Errorf("%w: x coordinate zero", ErrMalformedShare)
		}
		if seen[x] {
			return nil, fmt.Errorf("%w: duplicate share %d", ErrInconsistentShares, x)
		}
		seen[x] = true
		xs[i] = x
	}

	secret := make([]byte, size-1)
	ys := make([]byte, len(shares))
	for byteIndex := range secret {
		for i, s := range shares {
			ys[i] = s[byteIndex]
		}
		value, err := interpolateAtZero(xs, ys)
		if err != nil {
			return nil, err
		}
		secret[byteIndex] = value
	}
	return secret, nil
}

// randomPolynomial builds coefficients with the secret byte as the constant
// term, so evaluating at zero returns the secret.
func randomPolynomial(intercept byte, degree int) ([]byte, error) {
	coefficients := make([]byte, degree+1)
	coefficients[0] = intercept

	if degree > 0 {
		if _, err := rand.Read(coefficients[1:]); err != nil {
			return nil, fmt.Errorf("shamir: reading randomness: %w", err)
		}
		// The leading coefficient must be non-zero, or the polynomial has a
		// lower degree than the threshold implies and fewer shares than
		// advertised would suffice.
		for coefficients[degree] == 0 {
			if _, err := rand.Read(coefficients[degree : degree+1]); err != nil {
				return nil, fmt.Errorf("shamir: reading randomness: %w", err)
			}
		}
	}
	return coefficients, nil
}

// evaluate computes the polynomial at x using Horner's method.
func evaluate(coefficients []byte, x byte) byte {
	if x == 0 {
		return coefficients[0]
	}
	result := coefficients[len(coefficients)-1]
	for i := len(coefficients) - 2; i >= 0; i-- {
		result = add(mul(result, x), coefficients[i])
	}
	return result
}

// interpolateAtZero recovers the constant term by Lagrange interpolation.
func interpolateAtZero(xs, ys []byte) (byte, error) {
	var result byte
	for i, xi := range xs {
		basis := byte(1)
		for j, xj := range xs {
			if i == j {
				continue
			}
			// Evaluated at zero, each term is xj / (xj - xi); subtraction in
			// this field is XOR.
			denominator := add(xi, xj)
			term, err := div(xj, denominator)
			if err != nil {
				return 0, err
			}
			basis = mul(basis, term)
		}
		result = add(result, mul(ys[i], basis))
	}
	return result, nil
}
