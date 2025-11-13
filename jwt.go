package jwt

import (
	"errors"
	"fmt"
	"math"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/dobyte/jwt/internal/conv"
	"github.com/golang-jwt/jwt/v5"
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
	opts          *options
	secretKey     []byte
	publicKey     interface{}
	privateKey    interface{}
	signingMethod jwt.SigningMethod
	once          sync.Once
	http          *Http
}

func NewJWT(opts ...Option) (*JWT, error) {
	j := &JWT{opts: defaultOptions()}
	for _, opt := range opts {
		opt(j.opts)
	}

	if err := j.init(); err != nil {
		return nil, err
	}

	return j, nil
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
			return nil, ErrMissingIdentity
		}
	}

	var (
		claims    = make(jwt.MapClaims)
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
		return nil, ErrMissingToken
	}

	oldClaims, err := j.parseToken(token, ignoreExpired...)
	if err != nil {
		return nil, err
	}

	if len(ignoreExpired) == 0 || !ignoreExpired[0] {
		if (int64(oldClaims[jwtIssueAt].(float64)) + int64(j.opts.refreshDuration/time.Second)) < time.Now().Unix() {
			return nil, ErrExpiredToken
		}
	}

	if err = j.verifyIdentity(oldClaims, len(ignoreExpired) > 0 && ignoreExpired[0]); err != nil {
		return nil, err
	}

	now := time.Now()

	expiredAt := now.Add(j.opts.validDuration)
	refreshAt := now.Add(j.opts.refreshDuration)

	newClaims := make(jwt.MapClaims)
	for k, v := range oldClaims {
		newClaims[k] = v
	}

	newClaims[jwtIssueAt] = now.Unix()
	newClaims[jwtExpired] = expiredAt.Unix()
	newClaims[jwtId] = strconv.FormatInt(now.UnixNano(), 10)

	if token, err = j.signToken(newClaims); err != nil {
		return nil, err
	}

	if err = j.saveIdentity(newClaims[j.opts.identityKey], newClaims[jwtId]); err != nil {
		return nil, err
	}

	return &Token{
		Token:     token,
		ExpiredAt: expiredAt,
		RefreshAt: refreshAt,
	}, nil
}

// DestroyToken Destroy a token.
func (j *JWT) DestroyToken(token string, ignoreExpired ...bool) error {
	if j.opts.identityKey == "" {
		return nil
	}

	if j.opts.store == nil {
		return nil
	}

	claims, err := j.parseToken(token, ignoreExpired...)
	if err != nil {
		return err
	}

	identity, ok := claims[j.opts.identityKey]
	if !ok {
		return ErrMissingIdentity
	}

	if err = j.verifyIdentity(claims, len(ignoreExpired) > 0 && ignoreExpired[0]); err != nil {
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

	if err = j.verifyIdentity(claims, len(ignoreExpired) > 0 && ignoreExpired[0]); err != nil {
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
		return nil, ErrMissingIdentity
	}

	payload, err := j.ExtractPayload(token, ignoreExpired...)
	if err != nil {
		return nil, err
	}

	identity, ok := payload[j.opts.identityKey]
	if !ok {
		return nil, ErrMissingIdentity
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
func (j *JWT) signToken(claims jwt.MapClaims) (string, error) {
	jt := jwt.NewWithClaims(j.signingMethod, claims)

	switch j.opts.signAlgorithm {
	case HS256, HS384, HS512:
		return jt.SignedString(j.secretKey)
	default:
		return jt.SignedString(j.privateKey)
	}
}

// Parses and returns payload from the token.
func (j *JWT) parseToken(token string, ignoreExpired ...bool) (jwt.MapClaims, error) {
	if token == "" {
		return nil, ErrMissingToken
	}

	jt, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if j.signingMethod != t.Method {
			return nil, ErrSignAlgorithmNotMatch
		}

		switch j.opts.signAlgorithm {
		case HS256, HS384, HS512:
			return j.secretKey, nil
		default:
			return j.publicKey, nil
		}
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			if len(ignoreExpired) > 0 && ignoreExpired[0] {
				// ignore token expired error
			} else {
				return nil, ErrExpiredToken
			}
		} else {
			return nil, ErrInvalidToken
		}
	}

	if jt == nil {
		return nil, ErrInvalidToken
	}

	claims := jt.Claims.(jwt.MapClaims)

	if _, ok := claims[jwtId]; !ok {
		return nil, ErrInvalidToken
	}

	if _, ok := claims[jwtIssueAt]; !ok {
		return nil, ErrInvalidToken
	}

	if _, ok := claims[jwtExpired]; !ok {
		return nil, ErrInvalidToken
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
func (j *JWT) verifyIdentity(claims jwt.MapClaims, ignoreMissed bool) error {
	if j.opts.identityKey == "" {
		return nil
	}

	if _, ok := claims[j.opts.identityKey]; !ok {
		return ErrMissingIdentity
	}

	if j.opts.store == nil {
		return nil
	}

	key := fmt.Sprintf(defaultIdentityKey, j.opts.identityKey, conv.String(claims[j.opts.identityKey]))

	v, err := j.opts.store.Get(j.opts.ctx, key)
	if err != nil {
		return err
	}

	if oldJid := conv.String(v); oldJid == "" {
		if ignoreMissed {
			return nil
		} else {
			return ErrInvalidToken
		}
	} else if conv.String(claims[jwtId]) != oldJid {
		return ErrAuthElsewhere
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

func (j *JWT) init() error {
	switch j.opts.signAlgorithm {
	case HS256, HS384, HS512:
		if j.opts.secretKey == "" {
			return ErrInvalidSecretKey
		} else {
			j.secretKey = []byte(j.opts.secretKey)
		}
	case RS256, RS384, RS512, ES256, ES384, ES512:
		pub, err := loadKey(j.opts.publicKey)
		if err != nil {
			return err
		}

		if len(pub) == 0 {
			return ErrInvalidPublicKey
		}

		prv, err := loadKey(j.opts.privateKey)
		if err != nil {
			return err
		}

		if len(prv) == 0 {
			return ErrInvalidPrivateKey
		}

		switch j.opts.signAlgorithm {
		case RS256, RS384, RS512:
			if pubKey, err := jwt.ParseRSAPublicKeyFromPEM(pub); err != nil {
				return err
			} else {
				j.publicKey = pubKey
			}

			if prvKey, err := jwt.ParseRSAPrivateKeyFromPEM(prv); err != nil {
				return err
			} else {
				j.privateKey = prvKey
			}
		case ES256, ES384, ES512:
			if pubKey, err := jwt.ParseECPublicKeyFromPEM(pub); err != nil {
				return err
			} else {
				j.publicKey = pubKey
			}

			if prvKey, err := jwt.ParseECPrivateKeyFromPEM(prv); err != nil {
				return err
			} else {
				j.privateKey = prvKey
			}
		}
	default:
		return ErrInvalidSignAlgorithm
	}

	j.signingMethod = jwt.GetSigningMethod(j.opts.signAlgorithm.String())

	return nil
}

func loadKey(key string) ([]byte, error) {
	if fileInfo, err := os.Stat(key); err != nil {
		return []byte(key), nil
	} else {
		if fileInfo.Size() == 0 {
			return nil, nil
		}
		return os.ReadFile(key)
	}
}
