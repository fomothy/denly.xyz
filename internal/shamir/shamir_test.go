package shamir

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
)

func TestSplitCombineRoundTrip(t *testing.T) {
	secret := []byte("a 32-byte content key for a switch")

	shares, err := Split(secret, 5, 3)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	if len(shares) != 5 {
		t.Fatalf("got %d shares, want 5", len(shares))
	}

	got, err := Combine(shares[:3])
	if err != nil {
		t.Fatalf("Combine: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Errorf("reconstructed %q, want %q", got, secret)
	}
}

// The guarantee guardians are relying on: any K of them can open it, so it
// must not matter which K show up.
func TestEverySubsetOfThresholdSizeReconstructs(t *testing.T) {
	secret := []byte("threshold secret")
	const parts, threshold = 6, 3

	shares, err := Split(secret, parts, threshold)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}

	subsets := 0
	for i := 0; i < parts; i++ {
		for j := i + 1; j < parts; j++ {
			for k := j + 1; k < parts; k++ {
				got, err := Combine([]Share{shares[i], shares[j], shares[k]})
				if err != nil {
					t.Fatalf("Combine(%d,%d,%d): %v", i, j, k, err)
				}
				if !bytes.Equal(got, secret) {
					t.Fatalf("subset (%d,%d,%d) reconstructed the wrong secret", i, j, k)
				}
				subsets++
			}
		}
	}
	if subsets != 20 { // C(6,3)
		t.Errorf("checked %d subsets, expected 20", subsets)
	}
}

// The other half of the guarantee: one guardian short must learn nothing. A
// below-threshold combine may return bytes, but they must never be the secret.
func TestBelowThresholdNeverYieldsTheSecret(t *testing.T) {
	secret := []byte("no fewer shares may open this")

	shares, err := Split(secret, 5, 4)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}

	// Every 3-subset of a 4-of-5 split.
	for i := 0; i < 5; i++ {
		for j := i + 1; j < 5; j++ {
			for k := j + 1; k < 5; k++ {
				got, err := Combine([]Share{shares[i], shares[j], shares[k]})
				if err != nil {
					continue // refusing is also correct
				}
				if bytes.Equal(got, secret) {
					t.Fatalf("shares %d,%d,%d reconstructed the secret below the threshold", i, j, k)
				}
			}
		}
	}
}

func TestMoreThanThresholdStillWorks(t *testing.T) {
	secret := []byte("extra shares are harmless")

	shares, err := Split(secret, 7, 3)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	got, err := Combine(shares) // all seven
	if err != nil {
		t.Fatalf("Combine: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Error("combining every share did not reconstruct the secret")
	}
}

func TestSharesAreNotTheSecret(t *testing.T) {
	secret := []byte("recognisable plaintext marker")

	shares, err := Split(secret, 3, 2)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	for i, s := range shares {
		if bytes.Contains(s, secret) {
			t.Errorf("share %d contains the secret verbatim", i)
		}
	}
}

// x=0 evaluates to the secret itself, so no share may carry it.
func TestNoShareUsesTheZeroCoordinate(t *testing.T) {
	shares, err := Split([]byte("x"), 10, 2)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	for i, s := range shares {
		x, err := s.X()
		if err != nil {
			t.Fatalf("share %d: %v", i, err)
		}
		if x == 0 {
			t.Errorf("share %d uses x=0, which is the secret", i)
		}
	}
}

func TestSplitRejectsBadParameters(t *testing.T) {
	secret := []byte("s")

	cases := []struct {
		name             string
		parts, threshold int
	}{
		{"threshold above parts", 3, 4},
		{"threshold of one", 3, 1},
		{"zero parts", 0, 2},
		{"one part", 1, 2},
		{"too many parts", 256, 2},
		{"negative threshold", 3, -1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Split(secret, c.parts, c.threshold); !errors.Is(err, ErrBadParameters) {
				t.Errorf("err = %v, want ErrBadParameters", err)
			}
		})
	}
}

func TestSplitRejectsEmptySecret(t *testing.T) {
	if _, err := Split(nil, 3, 2); err == nil {
		t.Error("Split accepted an empty secret")
	}
}

func TestCombineRejectsBadInput(t *testing.T) {
	shares, err := Split([]byte("secret"), 4, 2)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}

	if _, err := Combine(shares[:1]); !errors.Is(err, ErrTooFewShares) {
		t.Errorf("one share: err = %v, want ErrTooFewShares", err)
	}

	// Duplicate shares would make the interpolation divide by zero and, worse,
	// would let one guardian pretend to be two.
	if _, err := Combine([]Share{shares[0], shares[0]}); !errors.Is(err, ErrInconsistentShares) {
		t.Errorf("duplicate shares: err = %v, want ErrInconsistentShares", err)
	}

	mismatched := []Share{shares[0], append(Share{}, append(shares[1], 0x00)...)}
	if _, err := Combine(mismatched); !errors.Is(err, ErrInconsistentShares) {
		t.Errorf("mismatched lengths: err = %v, want ErrInconsistentShares", err)
	}

	zeroX := append(Share{}, shares[0]...)
	zeroX[len(zeroX)-1] = 0
	if _, err := Combine([]Share{zeroX, shares[1]}); !errors.Is(err, ErrMalformedShare) {
		t.Errorf("zero x: err = %v, want ErrMalformedShare", err)
	}
}

// Shamir provides no integrity: a wrong share yields a wrong secret rather
// than an error. Callers must authenticate the result, so this documents the
// property rather than pretending otherwise.
func TestWrongSharesProduceWrongOutputNotAnError(t *testing.T) {
	a, err := Split([]byte("secret one"), 3, 2)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	b, err := Split([]byte("secret two"), 3, 2)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}

	got, err := Combine([]Share{a[0], b[1]})
	if err != nil {
		return // refusing is acceptable too
	}
	if bytes.Equal(got, []byte("secret one")) || bytes.Equal(got, []byte("secret two")) {
		t.Error("mixing shares from different splits reconstructed a real secret")
	}
}

func TestBinarySecretsSurvive(t *testing.T) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatalf("rand: %v", err)
	}
	// Zero bytes are the case a naive implementation gets wrong.
	secret[0], secret[15], secret[31] = 0, 0, 0

	shares, err := Split(secret, 5, 3)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	got, err := Combine([]Share{shares[4], shares[0], shares[2]})
	if err != nil {
		t.Fatalf("Combine: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Error("a secret containing zero bytes did not round-trip")
	}
}

func TestSplitIsRandomised(t *testing.T) {
	secret := []byte("same secret both times")

	first, err := Split(secret, 3, 2)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	second, err := Split(secret, 3, 2)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}

	if bytes.Equal(first[0], second[0]) {
		t.Error("splitting the same secret twice produced identical shares")
	}
}

func TestMaximumParts(t *testing.T) {
	shares, err := Split([]byte("k"), MaxParts, 2)
	if err != nil {
		t.Fatalf("Split at MaxParts: %v", err)
	}
	if len(shares) != MaxParts {
		t.Errorf("got %d shares, want %d", len(shares), MaxParts)
	}
	if _, err := Combine(shares[:2]); err != nil {
		t.Errorf("Combine: %v", err)
	}
}

// Field arithmetic identities, since everything above rests on them.
func TestFieldArithmetic(t *testing.T) {
	for i := 0; i < 256; i++ {
		a := byte(i)
		if got := mul(a, 0); got != 0 {
			t.Fatalf("mul(%d, 0) = %d, want 0", a, got)
		}
		if got := mul(a, 1); got != a {
			t.Fatalf("mul(%d, 1) = %d, want %d", a, got, a)
		}
		if got := add(a, a); got != 0 {
			t.Fatalf("add(%d, %d) = %d, want 0", a, a, got)
		}
		if a != 0 {
			q, err := div(a, a)
			if err != nil {
				t.Fatalf("div(%d, %d): %v", a, a, err)
			}
			if q != 1 {
				t.Fatalf("div(%d, %d) = %d, want 1", a, a, q)
			}
		}
	}
	if _, err := div(1, 0); err == nil {
		t.Error("div by zero did not error")
	}
}
