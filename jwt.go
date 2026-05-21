package jwt

import (
	"errors"
	"fmt"
	"maps"
	"math"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/dobyte/jwt/internal/conv"
	"github.com/golang-jwt/jwt/v5"
)

const (
	defaultSubjectKey = "jwt:%s:subject:%s"
)

type Token struct {
	Token     string    `json:"token"`
	ExpiredAt time.Time `json:"expired_at"`
	RefreshAt time.Time `json:"refresh_at"`
}

type JWT struct {
	opts          *options
	secretKey     []byte
	publicKey     any
	privateKey    any
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
func (j *JWT) GenerateToken(subject string, payload ...Payload) (*Token, error) {
	var (
		claims    = make(jwt.MapClaims)
		now       = time.Now()
		expiredAt = now.Add(j.opts.validDuration)
		refreshAt = now.Add(j.opts.refreshDuration)
		uuid      = strconv.FormatInt(now.UnixNano(), 10)
	)

	claims[claimUUID] = uuid
	claims[claimIssuer] = j.opts.issuer
	claims[claimIssueAt] = now.Unix()
	claims[claimAudience] = j.opts.audience
	claims[claimExpired] = expiredAt.Unix()
	claims[claimSubject] = subject

	if len(payload) > 0 {
		for k, v := range payload[0] {
			switch k {
			case claimUUID, claimAudience, claimExpired, claimIssueAt, claimIssuer, claimNotBefore, claimSubject:
				// ignore the standard claims
			default:
				claims[k] = v
			}
		}
	}

	token, err := j.doSignToken(claims)
	if err != nil {
		return nil, err
	}

	if err = j.doSaveSubject(subject, uuid); err != nil {
		return nil, err
	}

	return &Token{
		Token:     token,
		ExpiredAt: expiredAt,
		RefreshAt: refreshAt,
	}, nil
}

// RefreshToken Retreads and returns a new token object depend on old token.
// By default, the token expired error doesn't be ignored.
// You can ignore expired error by setting the `isOmitExpired` parameter.
func (j *JWT) RefreshToken(token string, isOmitExpired ...bool) (*Token, error) {
	payload, err := j.ParseToken(token, isOmitExpired...)
	if err != nil {
		return nil, err
	}

	var (
		now       = time.Now()
		claims    = make(jwt.MapClaims)
		uuid      = strconv.FormatInt(now.UnixNano(), 10)
		expiredAt = now.Add(j.opts.validDuration)
		refreshAt = now.Add(j.opts.refreshDuration)
	)

	maps.Copy(claims, payload)
	claims[claimUUID] = strconv.FormatInt(now.UnixNano(), 10)
	claims[claimIssuer] = j.opts.issuer
	claims[claimIssueAt] = now.Unix()
	claims[claimAudience] = j.opts.audience
	claims[claimExpired] = expiredAt.Unix()

	if token, err = j.doSignToken(claims); err != nil {
		return nil, err
	}

	if err = j.doSaveSubject(payload.Subject(), uuid); err != nil {
		return nil, err
	}

	return &Token{
		Token:     token,
		ExpiredAt: expiredAt,
		RefreshAt: refreshAt,
	}, nil
}

// ParseToken Parses and returns payload from the token.
// By default, The token expiration errors will not be ignored.
// The payload is nil when the token expiration errors not be ignored.
// You can ignore expired error by setting the `isOmitExpired` parameter.
func (j *JWT) ParseToken(token string, isOmitExpired ...bool) (Payload, error) {
	if token == "" {
		return nil, ErrMissingToken
	}

	claims, err := j.doParseToken(token, isOmitExpired...)
	if err != nil {
		return nil, err
	}

	if len(isOmitExpired) == 0 || !isOmitExpired[0] {
		if (int64(claims[claimIssueAt].(float64)) + int64(j.opts.refreshDuration/time.Second)) < time.Now().Unix() {
			return nil, ErrExpiredToken
		}
	}

	uuid, ok := claims[claimUUID]
	if !ok {
		return nil, ErrMissingSubject
	}

	subject, ok := claims[claimSubject]
	if !ok {
		return nil, ErrMissingSubject
	}

	if err = j.doVerifySubject(conv.String(subject), conv.String(uuid), len(isOmitExpired) > 0 && isOmitExpired[0]); err != nil {
		return nil, err
	}

	payload := make(Payload)

	maps.Copy(payload, claims)

	return payload, nil
}

// DestroyToken Destroy a token.
func (j *JWT) DestroyToken(token string, isOmitExpired ...bool) error {
	if j.opts.store == nil {
		return nil
	}

	payload, err := j.ParseToken(token, isOmitExpired...)
	if err != nil {
		return err
	}

	return j.doRemoveSubject(payload.Subject())
}

// DestroyTokenBySubject Destroy all of the tokens with the subject.
func (j *JWT) DestroyTokenBySubject(subject string) error {
	return j.doRemoveSubject(subject)
}

// Signings and returns a token depend on the claims.
func (j *JWT) doSignToken(claims jwt.MapClaims) (string, error) {
	jt := jwt.NewWithClaims(j.signingMethod, claims)

	switch j.opts.signAlgorithm {
	case HS256, HS384, HS512:
		return jt.SignedString(j.secretKey)
	default:
		return jt.SignedString(j.privateKey)
	}
}

// Parses and returns payload from the token.
func (j *JWT) doParseToken(token string, isOmitExpired ...bool) (jwt.MapClaims, error) {
	if token == "" {
		return nil, ErrMissingToken
	}

	jt, err := jwt.Parse(token, func(t *jwt.Token) (any, error) {
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
			if len(isOmitExpired) > 0 && isOmitExpired[0] {
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

	if _, ok := claims[claimUUID]; !ok {
		return nil, ErrInvalidToken
	}

	if _, ok := claims[claimIssueAt]; !ok {
		return nil, ErrInvalidToken
	}

	if _, ok := claims[claimExpired]; !ok {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

// save subject mark.
func (j *JWT) doSaveSubject(subject, uuid string) error {
	if j.opts.store == nil {
		return nil
	}

	var (
		key      = fmt.Sprintf(defaultSubjectKey, j.opts.issuer, subject)
		duration = time.Duration(math.Max(float64(j.opts.validDuration), float64(j.opts.refreshDuration)))
	)

	return j.opts.store.Set(j.opts.ctx, key, uuid, duration)
}

// verify identification mark.
func (j *JWT) doVerifySubject(subject, uuid string, isOmitExpired bool) error {
	if j.opts.store == nil {
		return nil
	}

	key := fmt.Sprintf(defaultSubjectKey, j.opts.issuer, subject)

	v, err := j.opts.store.Get(j.opts.ctx, key)
	if err != nil {
		return err
	}

	if old := conv.String(v); old == "" {
		if isOmitExpired {
			return nil
		} else {
			return ErrInvalidToken
		}
	} else if conv.String(uuid) != old {
		return ErrAuthElsewhere
	}

	return nil
}

// remove subject mark.
func (j *JWT) doRemoveSubject(subject string) error {
	if j.opts.store == nil {
		return nil
	}

	key := fmt.Sprintf(defaultSubjectKey, j.opts.issuer, subject)

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

	if j.opts.refreshDuration == 0 {
		j.opts.refreshDuration = j.opts.validDuration / 2
	}

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
