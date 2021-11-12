package jwt

import "errors"

var (
	// indicates JWT token is missing
	errMissingToken = errors.New("token is missing")

	// indicates JWT token has expired. Can't refresh.
	errExpiredToken = errors.New("token is expired")

	// indicates auth header is invalid, could for example have the wrong issuer
	errInvalidToken = errors.New("token is invalid")

	errIdentityMissing = errors.New("identity is missing")

	errAuthElsewhere = errors.New("auth elsewhere")

	//
	errSigningMethodNotMatch = errors.New("signing method does not match")

	// indicates that the signing signMethod is invalid, needs to be HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384 and ES512
	errInvalidSigningMethod = errors.New("invalid signing method")

	// indicates that the given secret key is invalid
	errInvalidSecretKey = errors.New("invalid secret key")

	// indicates that the given private key is invalid
	errInvalidPrivateKey = errors.New("invalid private key")

	// indicates the the given public key is invalid
	errInvalidPublicKey = errors.New("invalid public key")
)

func IsMissingToken(err error) bool {
	return errors.Is(err, errMissingToken)
}

func IsInvalidToken(err error) bool {
	return errors.Is(err, errInvalidToken)
}

func IsExpiredToken(err error) bool {
	return errors.Is(err, errExpiredToken)
}
