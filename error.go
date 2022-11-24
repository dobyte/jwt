package jwt

import "errors"

var (
	// indicates JWT token is missing
	errMissingToken = errors.New("token is missing")

	// indicates JWT token has expired. Can't refresh.
	errExpiredToken = errors.New("token is expired")

	// indicates auth header is invalid, could for example have the wrong issuer
	errInvalidToken = errors.New("token is invalid")

	// indicates that there is no corresponding identity information in the payload
	errMissingIdentity = errors.New("identity is missing")

	// indicates that the same identity is logged in elsewhere
	errAuthElsewhere = errors.New("auth elsewhere")

	// indicates that the signing method of the token is inconsistent with the configured signing method
	errSignAlgorithmNotMatch = errors.New("sign algorithm does not match")

	// indicates that the sign algorithm is invalid, must be one of HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384 and ES512
	errInvalidSignAlgorithm = errors.New("invalid sign algorithm")

	// indicates that the given secret cacheKey is invalid
	errInvalidSecretKey = errors.New("invalid secret cacheKey")

	// indicates that the given private cacheKey is invalid
	errInvalidPrivateKey = errors.New("invalid private cacheKey")

	// indicates the given public cacheKey is invalid
	errInvalidPublicKey = errors.New("invalid public cacheKey")
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

func IsAuthElsewhere(err error) bool {
	return errors.Is(err, errAuthElsewhere)
}

func IsIdentityMissing(err error) bool {
	return errors.Is(err, errMissingIdentity)
}

func IsInvalidSignAlgorithm(err error) bool {
	return errors.Is(err, errInvalidSignAlgorithm)
}
