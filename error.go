package jwt

import "errors"

var (
	// ErrMissingSecretKey indicates Secret key is required
	ErrMissingSecretKey = NewError("secret key is required", ErrorMissingSecretKey)

	// ErrFailedTokenCreation indicates JWT Token failed to create, reason unknown
	ErrFailedTokenCreation = NewError("failed to create JWT Token", ErrorFailedTokenCreation)

	// ErrFailedTokenDestroy indicates JWT Token failed to destroy, reason unknown
	ErrFailedTokenDestroy = NewError("failed to destroy JWT Token", ErrorFailedTokenDestroy)

	// ErrExpiredToken indicates JWT token has expired. Can't refresh.
	ErrExpiredToken = NewError("token is expired", ErrorExpiredToken)

	// ErrAuthElsewhere authorize elsewhere.
	ErrAuthorizeElsewhere = NewError("sign in elsewhere", ErrorAuthorizeElsewhere)

	// ErrEmptyAuthHeader can be thrown if authing with a HTTP header, the Auth header needs to be set
	ErrEmptyAuthHeader = NewError("auth header is empty", ErrorEmptyAuthHeader)

	// ErrMissingExpField missing exp field in token
	ErrMissingExpField = NewError("missing exp field", ErrorMissingExpField)

	// ErrWrongFormatOfExp field must be float64 format
	ErrWrongFormatOfExp = NewError("exp must be float64 format", ErrorWrongFormatOfExp)

	// ErrInvalidToken indicates auth header is invalid, could for example have the wrong Realm name
	ErrInvalidToken = NewError("token is invalid", ErrorInvalidToken)

	// ErrEmptyToken can be thrown if authing token is invalid, the token variable is empty
	ErrEmptyToken = NewError("token is empty", ErrorEmptyToken)

	// ErrInvalidAuthHeader indicates auth header is invalid, could for example have the wrong Realm name
	ErrInvalidAuthHeader = errors.New("auth header is invalid", ErrorInvalidAuthHeader)

	// ErrEmptyQueryToken can be thrown if authing with URL Query, the query token variable is empty
	ErrEmptyQueryToken = errors.New("query token is empty", ErrorEmptyQueryToken)

	// ErrEmptyCookieToken can be thrown if authing with a cookie, the token cookie is empty
	ErrEmptyCookieToken = errors.New("cookie token is empty")

	// ErrEmptyParamToken can be thrown if authing with parameter in path, the parameter in path is empty
	ErrEmptyParamToken = errors.New("parameter token is empty")

	// ErrInvalidSigningAlgorithm indicates signing algorithm is invalid, needs to be HS256, HS384, HS512, RS256, RS384 or RS512
	ErrInvalidSigningAlgorithm = errors.New("invalid signing algorithm")

	// ErrNoPrivateKeyFile indicates that the given private key is unreadable
	ErrNoPrivateKeyFile = errors.New("private key file unreadable")

	// ErrNoPublicKeyFile indicates that the given public key is unreadable
	ErrNoPublicKeyFile = errors.New("public key file unreadable")

	// ErrInvalidPrivateKey indicates that the given private key is invalid
	errInvalidPrivateKey = errors.New("invalid private key")

	// indicates the the given public key is invalid
	errInvalidPublicKey = errors.New("invalid public key")
)
