package jwt

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"
	"unsafe"

	jwts "github.com/dgrijalva/jwt-go"
)

type (
	Payload map[string]interface{}

	JWT interface {
		// Middleware Implemented basic JWT permission authentication.
		Middleware(r *http.Request) (*http.Request, error)

		// GenerateToken Generates and returns a new token object with payload.
		GenerateToken(payload Payload) (*Token, error)

		// RefreshToken Generates and returns a new token object from.
		RefreshToken(r *http.Request) (*Token, error)

		// RetreadToken Retreads and returns a new token object depend on old token.
		// By default, the token expired error doesn't ignored.
		// You can ignore expired error by setting the `ignoreExpired` parameter.
		RetreadToken(token string, ignoreExpired ...bool) (*Token, error)

		// GetToken Get token from request.
		// By default, the token expired error doesn't ignored.
		// You can ignore expired error by setting the `ignoreExpired` parameter.
		GetToken(r *http.Request, ignoreExpired ...bool) (*Token, error)

		// GetPayload Retrieve payload from request.
		// By default, the token expired error doesn't ignored.
		// You can ignore expired error by setting the `ignoreExpired` parameter.
		GetPayload(r *http.Request, ignoreExpired ...bool) (payload Payload, err error)
	}
)

type Options struct {
	// Define the token's issuer.
	// Using example: frontend or backend.
	Issuer string

	// Define the token's expired time.
	// The default is 3600s.
	ExpiredTime int

	// Define the token's refresh time, Can't refreshed after the refresh time.
	// When the refresh time is not set, the default value is half of expired time.
	RefreshTime int

	// Define the token seek locations within requests.
	// Support header, form, cookie and query parameter.
	// Support to seek multiple locations, Separate multiple seek locations with commas.
	Locations string

	// Define the signing method for generate token.
	// Support multiple signing method such as HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384 and ES512
	SignMethod string

	// Define the secret key of HMAC.
	// Only support secret value.
	// The secret key is required, when the signing method is one of HS256, HS384 or HS512.
	SecretKey string

	// Define the public key of RSA or ECDSA.
	// Support file path or value.
	// The public key is required, when the signing method is one of RS256, RS384, RS512, ES256, ES384 and ES512.
	PublicKey string

	// Define the private key of RSA or ECDSA.
	// Support file path or value.
	// The private key is required, when the signing method is one of RS256, RS384, RS512, ES256, ES384 and ES512.
	PrivateKey string
}

type jwt struct {
	issuer          string
	signMethod      string
	expiredMode     int
	expiredTime     time.Duration
	refreshTime     time.Duration
	tokenCtxKey     string
	tokenSeeks      [][2]string
	rsaPublicKey    *rsa.PublicKey
	rsaPrivateKey   *rsa.PrivateKey
	ecdsaPublicKey  *ecdsa.PublicKey
	ecdsaPrivateKey *ecdsa.PrivateKey
	secretKey       []byte
}

type Token struct {
	Token     string    `json:"token"`
	ExpiredAt time.Time `json:"expired_at"`
	RefreshAt time.Time `json:"refresh_at"`
}

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

const (
	HS256 = "HS256"
	HS512 = "HS512"
	HS384 = "HS384"
	RS256 = "RS256"
	RS384 = "RS384"
	RS512 = "RS512"
	ES256 = "ES256"
	ES384 = "ES384"
	ES512 = "ES512"

	tokenSeekFromHeader  = "header"
	tokenSeekFromQuery   = "query"
	tokenSeekFromCookie  = "cookie"
	tokenSeekFromForm    = "form"
	tokenSeekFieldHeader = "Authorization"
	authorizationBearer  = "Bearer"

	defaultSignMethod     = HS256
	defaultExpirationTime = time.Hour
	defaultPayloadCtxKey  = "jwt_payload"
	defaultTokenCtxKey    = "jwt_token"
)

func NewJwt(opt *Options) (JWT, error) {
	j := new(jwt)
	j.setIssuer(opt.Issuer)
	j.setLocations(opt.Locations)
	j.setExpiredTime(opt.ExpiredTime)
	j.setRefreshTime(opt.RefreshTime)

	var err error

	if err = j.setSigningMethod(opt.SignMethod); err != nil {
		return nil, err
	}

	if j.isHMAC() {
		if err = j.setSecretKey(opt.SecretKey); err != nil {
			return nil, err
		}
	} else {
		if err = j.setPublicKey(opt.PublicKey); err != nil {
			return nil, err
		}

		if err = j.setPrivateKey(opt.PrivateKey); err != nil {
			return nil, err
		}
	}

	return j, nil
}

// Middleware Implemented basic JWT permission authentication.
func (j *jwt) Middleware(r *http.Request) (*http.Request, error) {
	payload, token, err := j.parseRequest(r)
	if err != nil {
		return nil, err
	}

	ctx := r.Context()
	ctx = context.WithValue(ctx, defaultPayloadCtxKey, payload)
	ctx = context.WithValue(ctx, defaultTokenCtxKey, token)

	return r.WithContext(ctx), nil
}

// GenerateToken Generates and returns a new token object with payload.
func (j *jwt) GenerateToken(payload Payload) (*Token, error) {
	var (
		claims    = make(jwts.MapClaims)
		now       = time.Now()
		expiredAt = now.Add(j.expiredTime)
		refreshAt = now.Add(j.refreshTime)
	)

	claims[jwtId] = now.UnixNano()
	claims[jwtIssuer] = j.issuer
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

	return &Token{
		Token:     token,
		ExpiredAt: expiredAt,
		RefreshAt: refreshAt,
	}, nil
}

// RefreshToken Generates and returns a new token object from.
func (j *jwt) RefreshToken(r *http.Request) (*Token, error) {
	return j.RetreadToken(j.seekToken(r), true)
}

// RetreadToken Retreads and returns a new token object depend on old token.
// By default, the token expired error doesn't ignored.
// You can ignore expired error by setting the `ignoreExpired` parameter.
func (j *jwt) RetreadToken(token string, ignoreExpired ...bool) (*Token, error) {
	var (
		err       error
		claims    jwts.MapClaims
		newClaims jwts.MapClaims
	)

	if token == "" {
		return nil, errMissingToken
	}

	claims, err = j.parseToken(token, ignoreExpired...)
	if err != nil {
		return nil, err
	}

	now := time.Now()

	if (int64(claims[jwtIssueAt].(float64)) + int64(j.refreshTime/time.Second)) < now.Unix() {
		return nil, errExpiredToken
	}

	newClaims = make(jwts.MapClaims)
	for k, v := range claims {
		newClaims[k] = v
	}

	expiredAt := now.Add(j.expiredTime)
	refreshAt := now.Add(j.refreshTime)

	newClaims[jwtIssueAt] = now.Unix()
	newClaims[jwtExpired] = expiredAt.Unix()

	token, err = j.signToken(newClaims)
	if err != nil {
		return nil, err
	}

	return &Token{
		Token:     token,
		ExpiredAt: expiredAt,
		RefreshAt: refreshAt,
	}, nil
}

// GetToken Retrieve token from request.
// By default, the token expired error doesn't ignored.
// You can ignore expired error by setting the `ignoreExpired` parameter.
func (j *jwt) GetToken(r *http.Request, ignoreExpired ...bool) (*Token, error) {
	var token string

	if v := r.Context().Value(defaultTokenCtxKey); v != nil {
		token = v.(string)
	} else if token = j.seekToken(r); token == "" {
		return nil, errMissingToken
	}

	claims, err := j.parseToken(token, ignoreExpired...)
	if err != nil {
		return nil, err
	}

	expiredAt := time.Unix(int64(claims[jwtExpired].(float64)), 0)
	refreshAt := time.Unix(int64(claims[jwtIssueAt].(float64)), 0).Add(j.refreshTime)

	return &Token{
		Token:     token,
		ExpiredAt: expiredAt,
		RefreshAt: refreshAt,
	}, nil
}

// GetPayload Retrieve payload from request.
// By default, the token expired error doesn't ignored.
// You can ignore expired error by setting the `ignoreExpired` parameter.
func (j *jwt) GetPayload(r *http.Request, ignoreExpired ...bool) (payload Payload, err error) {
	if v := r.Context().Value(defaultPayloadCtxKey); v != nil {
		payload = v.(Payload)
	} else {
		payload, _, err = j.parseRequest(r, ignoreExpired...)
	}

	return
}

// Parses and returns the payload and token from requests.
func (j *jwt) parseRequest(r *http.Request, ignoreExpired ...bool) (payload Payload, token string, err error) {
	if token = j.seekToken(r); token == "" {
		err = errMissingToken
		return
	}

	claims, err := j.parseToken(token, ignoreExpired...)
	if err != nil {
		return
	}

	payload = make(Payload)
	for k, v := range claims {
		switch k {
		case jwtAudience, jwtExpired, jwtId, jwtIssueAt, jwtIssuer, jwtNotBefore, jwtSubject:
			// ignore the standard claims
		default:
			payload[k] = v
		}
	}

	return
}

// Seeks and returns token from request.
// 1.from header    Authorization: Bearer ${token}
// 2.from query     ${url}?${key}=${token}
// 3.from cookie    Cookie: ${key}=${token}
// 4.from form      ${key}=${token}
func (j *jwt) seekToken(r *http.Request) (token string) {
	for _, item := range j.tokenSeeks {
		if len(token) > 0 {
			break
		}
		switch item[0] {
		case tokenSeekFromHeader:
			token = j.seekTokenFromHeader(r, item[1])
		case tokenSeekFromQuery:
			token = j.seekTokenFromQuery(r, item[1])
		case tokenSeekFromCookie:
			token = j.seekTokenFromCookie(r, item[1])
		case tokenSeekFromForm:
			token = j.seekTokenFromForm(r, item[1])
		}
	}

	return
}

// Seeks and returns JWT token from the headers of request.
func (j *jwt) seekTokenFromHeader(r *http.Request, key string) string {
	parts := strings.SplitN(r.Header.Get(key), " ", 2)
	if len(parts) != 2 || parts[0] != authorizationBearer {
		return ""
	}

	return parts[1]
}

// Seeks and returns JWT token from the query params of request.
func (j *jwt) seekTokenFromQuery(r *http.Request, key string) string {
	return r.URL.Query().Get(key)
}

// Seeks and returns JWT token from the cookies of request.
func (j *jwt) seekTokenFromCookie(r *http.Request, key string) string {
	cookie, _ := r.Cookie(key)
	return cookie.String()
}

// Seeks and returns JWT token from the post forms of request.
func (j *jwt) seekTokenFromForm(r *http.Request, key string) string {
	return r.Form.Get(key)
}

// Parses and returns a claims map from the token.
// By default, The token expiration errors will not be ignored.
// The claims is nil when the token expiration errors not be ignored.
func (j *jwt) parseToken(token string, ignoreExpired ...bool) (jwts.MapClaims, error) {
	jt, err := jwts.Parse(token, func(t *jwts.Token) (key interface{}, err error) {
		if jwts.GetSigningMethod(j.signMethod) != t.Method {
			err = errSigningMethodNotMatch
			return
		}

		switch {
		case j.isHMAC():
			key = j.secretKey
		case j.isRSA():
			key = j.rsaPublicKey
		case j.isECDSA():
			key = j.ecdsaPublicKey
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

	if _, ok := claims[jwtIssueAt]; !ok {
		return nil, errInvalidToken
	}

	if _, ok := claims[jwtExpired]; !ok {
		return nil, errInvalidToken
	}

	return jt.Claims.(jwts.MapClaims), nil
}

// Signings and returns a token depend on the claims.
func (j *jwt) signToken(claims jwts.MapClaims) (token string, err error) {
	jt := jwts.New(jwts.GetSigningMethod(j.signMethod))
	jt.Claims = claims

	switch {
	case j.isHMAC():
		token, err = jt.SignedString(j.secretKey)
	case j.isRSA():
		token, err = jt.SignedString(j.rsaPrivateKey)
	case j.isECDSA():
		token, err = jt.SignedString(j.ecdsaPrivateKey)
	}
	if err != nil {
		return
	}

	return
}

// Check whether the signing method is HMAC.
func (j *jwt) isHMAC() bool {
	switch j.signMethod {
	case HS256, HS384, HS512:
		return true
	}
	return false
}

// Check whether the signing method is RSA.
func (j *jwt) isRSA() bool {
	switch j.signMethod {
	case RS256, RS384, RS512:
		return true
	}
	return false
}

// Check whether the signing method is ECDSA.
func (j *jwt) isECDSA() bool {
	switch j.signMethod {
	case RS256, RS384, RS512:
		return true
	}
	return false
}

// Set signing method.
// Support multiple signing method such as HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384 and ES512
func (j *jwt) setSigningMethod(signingMethod string) error {
	switch signingMethod {
	case HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512:
		j.signMethod = signingMethod
	case "":
		j.signMethod = defaultSignMethod
	default:
		return errInvalidSigningMethod
	}

	return nil
}

// SetTokenLookup Set the token search location.
func (j *jwt) setLocations(tokenLookup string) {
	j.tokenSeeks = make([][2]string, 0)

	for _, method := range strings.Split(tokenLookup, ",") {
		parts := strings.Split(strings.TrimSpace(method), ":")
		k := strings.TrimSpace(parts[0])
		v := strings.TrimSpace(parts[1])
		switch k {
		case tokenSeekFromHeader, tokenSeekFromQuery, tokenSeekFromCookie, tokenSeekFromForm:
			j.tokenSeeks = append(j.tokenSeeks, [2]string{k, v})
		}
	}

	if len(j.tokenSeeks) == 0 {
		j.tokenSeeks = append(j.tokenSeeks, [2]string{tokenSeekFromHeader, tokenSeekFieldHeader})
	}
}

// Set the issuer of the token.
func (j *jwt) setIssuer(issuer string) {
	j.issuer = issuer
}

// Set expiration time.
// If only set the expiration time,
// The refresh time will automatically be set to half of the expiration time.
func (j *jwt) setExpiredTime(expirationTime int) {
	if expirationTime > 0 {
		j.expiredTime = time.Duration(expirationTime) * time.Second
	} else {
		j.expiredTime = defaultExpirationTime
	}
}

// Set refresh time.
// If only set the expiration time,
// The refresh time will automatically be set to half of the expiration time.
func (j *jwt) setRefreshTime(refreshTime int) {
	if refreshTime > 0 {
		j.refreshTime = time.Duration(refreshTime) * time.Second
	} else {
		j.refreshTime = j.expiredTime / 2
	}
}

// Set secret key.
func (j *jwt) setSecretKey(secretKey string) (err error) {
	if secretKey == "" {
		return errInvalidSecretKey
	}

	j.secretKey = stringToBytes(secretKey)

	return
}

// Set public key.
// Allow setting of public key file or public key.
func (j *jwt) setPublicKey(publicKey string) (err error) {
	if publicKey == "" {
		return errInvalidPublicKey
	}

	var (
		fileInfo os.FileInfo
		key      []byte
	)

	if fileInfo, err = os.Stat(publicKey); err != nil {
		key = stringToBytes(publicKey)
	} else {
		if fileInfo.Size() == 0 {
			return errInvalidPublicKey
		}

		if key, err = ioutil.ReadFile(publicKey); err != nil {
			return
		}
	}

	if j.isRSA() {
		if j.rsaPublicKey, err = jwts.ParseRSAPublicKeyFromPEM(key); err != nil {
			return
		}
	}

	if j.isECDSA() {
		if j.ecdsaPublicKey, err = jwts.ParseECPublicKeyFromPEM(key); err != nil {
			return
		}
	}

	return
}

// Set private key.
// Allow setting of private key file or private key.
func (j *jwt) setPrivateKey(privateKey string) (err error) {
	if privateKey == "" {
		return errInvalidPrivateKey
	}

	var (
		fileInfo os.FileInfo
		key      []byte
	)

	if fileInfo, err = os.Stat(privateKey); err != nil {
		key = stringToBytes(privateKey)
	} else {
		if fileInfo.Size() == 0 {
			return errInvalidPrivateKey
		}

		if key, err = ioutil.ReadFile(privateKey); err != nil {
			return
		}
	}

	if j.isRSA() {
		if j.rsaPrivateKey, err = jwts.ParseRSAPrivateKeyFromPEM(key); err != nil {
			return
		}
	}

	if j.isECDSA() {
		if j.ecdsaPrivateKey, err = jwts.ParseECPrivateKeyFromPEM(key); err != nil {
			return
		}
	}

	return
}

func stringToBytes(str string) []byte {
	return *(*[]byte)(unsafe.Pointer(&str))
}
