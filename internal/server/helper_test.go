package server

import (
	"errors"

	"github.com/fomothy/denly.xyz/internal/auth"
	"github.com/fomothy/denly.xyz/internal/shamir"
)

// signAsOwner signs a challenge with the test server's owner key, exercising
// the same construction a remote CLI would use.
func signAsOwner(s *Server, challenge string) (string, error) {
	if s.ownerKey == nil {
		return "", errors.New("test server has no owner secret key")
	}
	return auth.SignChallenge(s.ownerKey, challenge)
}

// toShares converts raw share bytes into the shamir type, so the API test can
// exercise the same guardian path a real guardian would.
func toShares(raw [][]byte) []shamir.Share {
	out := make([]shamir.Share, 0, len(raw))
	for _, r := range raw {
		out = append(out, shamir.Share(r))
	}
	return out
}
