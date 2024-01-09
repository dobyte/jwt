package jwt

import (
	"context"
	"time"
)

type Option func(o *options)

type SignAlgorithm string

func (s SignAlgorithm) String() string {
	return string(s)
}

const (
	HS256 SignAlgorithm = "HS256"
	HS512 SignAlgorithm = "HS512"
	HS384 SignAlgorithm = "HS384"

	RS256 SignAlgorithm = "RS256"
	RS384 SignAlgorithm = "RS384"
	RS512 SignAlgorithm = "RS512"

	ES256 SignAlgorithm = "ES256"
	ES384 SignAlgorithm = "ES384"
	ES512 SignAlgorithm = "ES512"
)

type options struct {
	ctx                      context.Context
	issuer                   string
	identityKey              string
	validDuration            time.Duration
	refreshDuration          time.Duration
	isSettingRefreshDuration bool
	signAlgorithm            SignAlgorithm
	secretKey                string
	publicKey                string
	privateKey               string
	lookupLocations          string
	store                    Store
}

func defaultOptions() *options {
	return &options{
		ctx:             context.Background(),
		validDuration:   2 * time.Hour,
		refreshDuration: time.Hour,
		signAlgorithm:   HS256,
	}
}

// WithIssuer Set the issuer of the token.
func WithIssuer(issuer string) Option {
	return func(o *options) { o.issuer = issuer }
}

// WithIdentityKey Set the identity key of the token.
// After opening the identification identifier and cache interface, the system will
// construct a unique authorization identifier for each token. If the same user is
// authorized to log in elsewhere, the previous token will no longer be valid.
func WithIdentityKey(identityKey string) Option {
	return func(o *options) { o.identityKey = identityKey }
}

// WithValidDuration Set token valid duration.
// If only set the valid duration,
// The refresh duration will automatically be set to half of the valid duration.
func WithValidDuration(duration int) Option {
	return func(o *options) {
		o.validDuration = time.Duration(duration) * time.Second
		if !o.isSettingRefreshDuration {
			o.refreshDuration = o.validDuration / 2
		}
	}
}

// WithRefreshDuration Set token refresh duration.
func WithRefreshDuration(duration int) Option {
	return func(o *options) {
		o.refreshDuration = time.Duration(duration) * time.Second
		o.isSettingRefreshDuration = true
	}
}

// WithSignAlgorithm Set signature algorithm.
// The secret key must be set when the signature algorithm is one of HS256, HS384 and HS512
// The public key and private key must be set when the signature algorithm is one of RS256, RS384 and RS512
// The public key and private key must be set when the signature algorithm is one of ES256, ES384 and ES512
func WithSignAlgorithm(signAlgorithm SignAlgorithm) Option {
	return func(o *options) { o.signAlgorithm = signAlgorithm }
}

// WithSecretKey Set secret key.
// The signature algorithm is one of HS256, HS384 and HS512
func WithSecretKey(secretKey string) Option {
	return func(o *options) { o.secretKey = secretKey }
}

// WithPublicPrivateKey Set public key and private key.
// The signature algorithm is one of RS256, RS384, RS512, ES256, ES384 and ES512
func WithPublicPrivateKey(publicKey, privateKey string) Option {
	return func(o *options) { o.publicKey, o.privateKey = publicKey, privateKey }
}

// WithLookupLocations Set the token lookup locations within requests.
// Support header, form, cookie and query parameter.
// Support to seek multiple locations, Separate multiple seek locations with commas.
func WithLookupLocations(locations string) Option {
	return func(o *options) { o.lookupLocations = locations }
}

// WithStore Set a store adapter for authentication.
func WithStore(store Store) Option {
	return func(o *options) { o.store = store }
}
