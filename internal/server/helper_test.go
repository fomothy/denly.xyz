package server

import (
	"errors"

	"github.com/fomothy/denly.xyz/internal/auth"
)

// signAsOwner signs a challenge with the test server's owner key, exercising
// the same construction a remote CLI would use.
func signAsOwner(s *Server, challenge string) (string, error) {
	if s.ownerKey == nil {
		return "", errors.New("test server has no owner secret key")
	}
	return auth.SignChallenge(s.ownerKey, challenge)
}
