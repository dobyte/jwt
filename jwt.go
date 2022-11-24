package jwt

import (
	"fmt"
	jwts "github.com/dgrijalva/jwt-go"
	"github.com/dobyte/jwt/internal/conv"
	"io/ioutil"
	"math"
	"os"
	"strconv"
	"sync"
	"time"
)

const (
	defaultIdentityKey = "jwt:%s:identity:%s"
)

const (
	jwtAudience    = "aud"
	jwtId          = "jti"
	jwtIssueAt     = "iat"
	jwtExpired     = "exp"
	jwtIssuer      = "iss"
	jwtNotBefore   = "nbf"
	jwtSubject     = "sub"
	noDetailReason = "no detail reason"
)

type Payload map[string]interface{}

type Token struct {
	Token     string    `json:"token"`
	ExpiredAt time.Time `json:"expired_at"`
	RefreshAt time.Time `json:"refresh_at"`
}

type JWT struct {
	opts       *options
	err        error
	secretKey  []byte
	publicKey  interface{}
	privateKey interface{}
	once       sync.Once
	http       *Http
}

func NewJWT(opts ...Option) *JWT {
	j := &JWT{opts: defaultOptions()}
	for _, opt := range opts {
		opt(j.opts)
	}
	j.init()

	return j
}

// Http Create a http jwt component
func (j *JWT) Http() *Http {
	j.once.Do(func() {
		j.http = NewHttp(j)
	})
	return j.http
}

// GenerateToken Generates and returns a new token object with payload.
func (j *JWT) GenerateToken(payload Payload) (*Token, error) {
	if j.opts.identityKey != "" {
		if _, ok := payload[j.opts.identityKey]; !ok {
			return nil, errMissingIdentity
		}
	}

	var (
		claims    = make(jwts.MapClaims)
		now       = time.Now()
		expiredAt = now.Add(j.opts.validDuration)
		refreshAt = now.Add(j.opts.refreshDuration)
		id        = strconv.FormatInt(now.UnixNano(), 10)
	)

	claims[jwtId] = id
	claims[jwtIssuer] = j.opts.issuer
	claims[jwtIssueAt] = now.Unix()
	claims[jwtExpired] = expiredAt.Unix()
	for k, v := range payload {
		switch k {
		case jwtAudience, jwtExpired, jwtId, jwtIssueAt, jwtIssuer, jwtNotBefore, jwtSubject:
			// ignore the standard claims
		default:
			claims[k] = v
		}
	}

	token, err := j.signToken(claims)
	if err != nil {
		return nil, err
	}

	if j.opts.identityKey != "" {
		if err = j.saveIdentity(payload[j.opts.identityKey], id); err != nil {
			return nil, err
		}
	}

	return &Token{
		Token:     token,
		ExpiredAt: expiredAt,
		RefreshAt: refreshAt,
	}, nil
}

// RefreshToken Retreads and returns a new token object depend on old token.
// By default, the token expired error doesn't be ignored.
// You can ignore expired error by setting the `ignoreExpired` parameter.
func (j *JWT) RefreshToken(token string, ignoreExpired ...bool) (*Token, error) {
	if token == "" {
		return nil, errMissingToken
	}

	var (
		err       error
		claims    jwts.MapClaims
		newClaims jwts.MapClaims
		now       = time.Now()
	)

	claims, err = j.parseToken(token, ignoreExpired...)
	if err != nil {
		return nil, err
	}

	if (int64(claims[jwtIssueAt].(float64)) + int64(j.opts.refreshDuration/time.Second)) < now.Unix() {
		return nil, errExpiredToken
	}

	newClaims = make(jwts.MapClaims)
	for k, v := range claims {
		newClaims[k] = v
	}

	expiredAt := now.Add(j.opts.validDuration)
	refreshAt := now.Add(j.opts.refreshDuration)

	newClaims[jwtIssueAt] = now.Unix()
	newClaims[jwtExpired] = expiredAt.Unix()
	newClaims[jwtId] = strconv.FormatInt(now.UnixNano(), 10)

	token, err = j.signToken(newClaims)
	if err != nil {
		return nil, err
	}

	object := &Token{Token: token, ExpiredAt: expiredAt, RefreshAt: refreshAt}

	if j.opts.identityKey == "" {
		return object, nil
	}

	if _, ok := claims[j.opts.identityKey]; !ok {
		return nil, errMissingIdentity
	}

	if err = j.verifyIdentity(claims, false); err != nil {
		return nil, err
	}

	if err = j.saveIdentity(newClaims[j.opts.identityKey], newClaims[jwtId]); err != nil {
		return nil, err
	}

	return object, nil
}

// DestroyToken Destroy a token.
func (j *JWT) DestroyToken(token string) error {
	if j.opts.identityKey == "" {
		return nil
	}

	if j.opts.store == nil {
		return nil
	}

	claims, err := j.parseToken(token, true)
	if err != nil {
		return err
	}

	identity, ok := claims[j.opts.identityKey]
	if !ok {
		return errMissingIdentity
	}

	if err = j.verifyIdentity(claims, true); err != nil {
		return err
	}

	return j.removeIdentity(identity)
}

// ExtractPayload Extracts and returns payload from the token.
// By default, The token expiration errors will not be ignored.
// The payload is nil when the token expiration errors not be ignored.
func (j *JWT) ExtractPayload(token string, ignoreExpired ...bool) (Payload, error) {
	claims, err := j.parseToken(token, ignoreExpired...)
	if err != nil {
		return nil, err
	}

	if err = j.verifyIdentity(claims, false); err != nil {
		return nil, err
	}

	payload := make(Payload)
	for k, v := range claims {
		switch k {
		case jwtAudience, jwtExpired, jwtId, jwtIssueAt, jwtIssuer, jwtNotBefore, jwtSubject:
			// ignore the standard claims
		default:
			payload[k] = v
		}
	}

	return payload, nil
}

// ExtractIdentity Retrieve identity from token.
// By default, the token expired error doesn't be ignored.
// You can ignore expired error by setting the `ignoreExpired` parameter.
func (j *JWT) ExtractIdentity(token string, ignoreExpired ...bool) (interface{}, error) {
	if j.opts.identityKey == "" {
		return nil, errMissingIdentity
	}

	payload, err := j.ExtractPayload(token, ignoreExpired...)
	if err != nil {
		return nil, err
	}

	identity, ok := payload[j.opts.identityKey]
	if !ok {
		return nil, errMissingIdentity
	}

	return identity, nil
}

// DestroyIdentity Destroy the identification mark.
func (j *JWT) DestroyIdentity(identity interface{}) error {
	return j.removeIdentity(identity)
}

// IdentityKey Retrieve identity key.
func (j *JWT) IdentityKey() string {
	return j.opts.identityKey
}

// Signings and returns a token depend on the claims.
func (j *JWT) signToken(claims jwts.MapClaims) (token string, err error) {
	if j.err != nil {
		err = j.err
		return
	}

	jt := jwts.New(jwts.GetSigningMethod(string(j.opts.signAlgorithm)))
	jt.Claims = claims

	switch j.opts.signAlgorithm {
	case HS256, HS384, HS512:
		token, err = jt.SignedString(j.secretKey)
	case RS256, RS384, RS512:
		token, err = jt.SignedString(j.privateKey)
	case ES256, ES384, ES512:
		token, err = jt.SignedString(j.privateKey)
	default:
		err = errInvalidSignAlgorithm
	}
	return
}

// Parses and returns payload from the token.
func (j *JWT) parseToken(token string, ignoreExpired ...bool) (jwts.MapClaims, error) {
	if j.err != nil {
		return nil, j.err
	}

	if token == "" {
		return nil, errMissingToken
	}

	jt, err := jwts.Parse(token, func(t *jwts.Token) (key interface{}, err error) {
		if jwts.GetSigningMethod(string(j.opts.signAlgorithm)) != t.Method {
			err = errSignAlgorithmNotMatch
			return
		}

		switch j.opts.signAlgorithm {
		case HS256, HS384, HS512:
			key = j.secretKey
		default:
			key = j.publicKey
		}
		return
	})
	if err != nil {
		switch e := err.(type) {
		case *jwts.ValidationError:
			switch e.Errors {
			case jwts.ValidationErrorExpired:
				if len(ignoreExpired) > 0 && ignoreExpired[0] {
					// ignore token expired error
				} else {
					return nil, errExpiredToken
				}
			default:
				return nil, errInvalidToken
			}
		default:
			return nil, errInvalidToken
		}
	}

	if jt == nil || !jt.Valid {
		return nil, errInvalidToken
	}

	claims := jt.Claims.(jwts.MapClaims)

	if _, ok := claims[jwtId]; !ok {
		return nil, errInvalidToken
	}

	if _, ok := claims[jwtIssueAt]; !ok {
		return nil, errInvalidToken
	}

	if _, ok := claims[jwtExpired]; !ok {
		return nil, errInvalidToken
	}

	return claims, nil
}

// save identification mark.
func (j *JWT) saveIdentity(identity, jid interface{}) error {
	if j.opts.identityKey == "" {
		return nil
	}

	if j.opts.store == nil {
		return nil
	}

	key := fmt.Sprintf(defaultIdentityKey, j.opts.identityKey, conv.String(identity))
	duration := time.Duration(math.Max(float64(j.opts.validDuration), float64(j.opts.refreshDuration)))

	return j.opts.store.Set(j.opts.ctx, key, conv.String(jid), duration)
}

// verify identification mark.
func (j *JWT) verifyIdentity(claims jwts.MapClaims, ignoreMissed bool) error {
	if j.opts.identityKey == "" {
		return nil
	}

	if j.opts.store == nil {
		return nil
	}

	var (
		jid      = claims[jwtId]
		identity = claims[j.opts.identityKey]
		key      = fmt.Sprintf(defaultIdentityKey, j.opts.identityKey, conv.String(identity))
	)

	v, err := j.opts.store.Get(j.opts.ctx, key)
	if err != nil {
		return err
	}

	oldJid := conv.String(v)
	if oldJid == "" {
		if ignoreMissed {
			return nil
		} else {
			return errInvalidToken
		}
	}

	if conv.String(jid) != oldJid {
		return errAuthElsewhere
	}

	return nil
}

// remove identification mark.
func (j *JWT) removeIdentity(identity interface{}) error {
	if j.opts.identityKey == "" {
		return nil
	}

	if j.opts.store == nil {
		return nil
	}

	key := fmt.Sprintf(defaultIdentityKey, j.opts.identityKey, conv.String(identity))

	_, err := j.opts.store.Remove(j.opts.ctx, key)
	return err
}

func (j *JWT) init() {
	switch j.opts.signAlgorithm {
	case HS256, HS384, HS512:
		if j.opts.secretKey == "" {
			j.err = errInvalidSecretKey
		} else {
			j.secretKey = []byte(j.opts.secretKey)
		}
	case RS256, RS384, RS512, ES256, ES384, ES512:
		pub, err := loadKey(j.opts.publicKey)
		if err != nil {
			j.err = err
			return
		}

		if len(pub) == 0 {
			j.err = errInvalidPublicKey
			return
		}

		prv, err := loadKey(j.opts.privateKey)
		if err != nil {
			j.err = err
			return
		}

		if len(prv) == 0 {
			j.err = errInvalidPrivateKey
			return
		}

		switch j.opts.signAlgorithm {
		case RS256, RS384, RS512:
			if pubKey, err := jwts.ParseRSAPublicKeyFromPEM(pub); err != nil {
				j.err = err
				return
			} else {
				j.publicKey = pubKey
			}

			if prvKey, err := jwts.ParseRSAPrivateKeyFromPEM(prv); err != nil {
				j.err = err
				return
			} else {
				j.privateKey = prvKey
			}
		case ES256, ES384, ES512:
			if pubKey, err := jwts.ParseECPublicKeyFromPEM(pub); err != nil {
				j.err = err
				return
			} else {
				j.publicKey = pubKey
			}

			if prvKey, err := jwts.ParseECPrivateKeyFromPEM(prv); err != nil {
				j.err = err
				return
			} else {
				j.privateKey = prvKey
			}
		}
	default:
		j.err = errInvalidSignAlgorithm
	}
}

func loadKey(key string) ([]byte, error) {
	if fileInfo, err := os.Stat(key); err != nil {
		return []byte(key), nil
	} else {
		if fileInfo.Size() == 0 {
			return nil, nil
		}
		return ioutil.ReadFile(key)
	}
}
