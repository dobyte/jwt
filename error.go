package jwt

const (
	ErrorMissingSecretKey uint32 = 1 << iota // Token is malformed
	ErrorExpiredToken
	ErrorEmptyAuthHeader
	ErrorMissingExpField
	ErrorWrongFormatOfExp
	ErrorInvalidPublicKey
	ErrorInvalidPrivateKey
	ErrorNoPublicKeyFile
	ErrorNoPrivateKeyFile
	ErrorInvalidSigningAlgorithm
	ErrorEmptyToken
	ErrorInvalidAuthHeader
	ErrorEmptyQueryToken
	ErrorEmptyCookieToken
	ErrorEmptyParamToken
	ErrorFailedTokenCreation
	ErrorFailedTokenDestroy
	ErrorInvalidToken
	ErrorAuthorizeElsewhere
)

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
	ErrInvalidAuthHeader = NewError("auth header is invalid", ErrorInvalidAuthHeader)

	// ErrEmptyQueryToken can be thrown if authing with URL Query, the query token variable is empty
	ErrEmptyQueryToken = NewError("query token is empty", ErrorEmptyQueryToken)

	// ErrEmptyCookieToken can be thrown if authing with a cookie, the token cookie is empty
	ErrEmptyCookieToken = NewError("cookie token is empty", ErrorEmptyCookieToken)

	// ErrEmptyParamToken can be thrown if authing with parameter in path, the parameter in path is empty
	ErrEmptyParamToken = NewError("parameter token is empty", ErrorEmptyParamToken)

	// ErrInvalidSigningAlgorithm indicates signing algorithm is invalid, needs to be HS256, HS384, HS512, RS256, RS384 or RS512
	ErrInvalidSigningAlgorithm = NewError("invalid signing algorithm", ErrorInvalidSigningAlgorithm)

	// ErrNoPrivateKeyFile indicates that the given private key is unreadable
	ErrNoPrivateKeyFile = NewError("private key file unreadable", ErrorNoPrivateKeyFile)

	// ErrNoPublicKeyFile indicates that the given public key is unreadable
	ErrNoPublicKeyFile = NewError("public key file unreadable", ErrorNoPublicKeyFile)

	// ErrInvalidPrivateKey indicates that the given private key is invalid
	ErrInvalidPrivateKey = NewError("private key invalid", ErrorInvalidPrivateKey)

	// ErrInvalidPublicKey indicates the the given public key is invalid
	ErrInvalidPublicKey = NewError("public key invalid", ErrorInvalidPublicKey)
)

type Error struct {
	Inner  error
	Errors uint32
	text   string
}

func NewError(errorText string, errorFlags uint32) *Error {
	return &Error{
		text:   errorText,
		Errors: errorFlags,
	}
}

// Validation error is an error type
func (o *Error) Error() string {
	if o.Inner != nil {
		return o.Inner.Error()
	}

	return o.text
}

// No errors
func (o *Error) valid() bool {
	return o.Errors == 0
}
