package jwt

import "errors"

var (
	// indicates JWT token is missing
	ErrMissingToken = errors.New("token is missing")

	// indicates JWT token has expired. Can't refresh.
	ErrExpiredToken = errors.New("token is expired")

	// indicates auth header is invalid, could for example have the wrong issuer
	ErrInvalidToken = errors.New("token is invalid")

	// indicates that there is no corresponding identity information in the payload
	ErrMissingIdentity = errors.New("identity is missing")

	// indicates that the same identity is logged in elsewhere
	ErrAuthElsewhere = errors.New("auth elsewhere")

	// indicates that the signing method of the token is inconsistent with the configured signing method
	ErrSignAlgorithmNotMatch = errors.New("sign algorithm does not match")

	// indicates that the sign algorithm is invalid, must be one of HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384 and ES512
	ErrInvalidSignAlgorithm = errors.New("invalid sign algorithm")

	// indicates that the given secret cacheKey is invalid
	ErrInvalidSecretKey = errors.New("invalid secret cacheKey")

	// indicates that the given private cacheKey is invalid
	ErrInvalidPrivateKey = errors.New("invalid private cacheKey")

	// indicates the given public cacheKey is invalid
	ErrInvalidPublicKey = errors.New("invalid public cacheKey")
)

func IsMissingToken(err error) bool {
	return errors.Is(err, ErrMissingToken)
}

func IsInvalidToken(err error) bool {
	return errors.Is(err, ErrInvalidToken)
}

func IsExpiredToken(err error) bool {
	return errors.Is(err, ErrExpiredToken)
}

func IsAuthElsewhere(err error) bool {
	return errors.Is(err, ErrAuthElsewhere)
}

func IsIdentityMissing(err error) bool {
	return errors.Is(err, ErrMissingIdentity)
}

func IsInvalidSignAlgorithm(err error) bool {
	return errors.Is(err, ErrInvalidSignAlgorithm)
}
