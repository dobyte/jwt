package jwt

import (
	"context"
	"crypto/rsa"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"
	"unsafe"
	
	"github.com/dgrijalva/jwt-go"
)

type (
	Algorithm string
)

type JWT interface {
	// SetExpireTime Set expiration time.
	SetExpireTime(expireTime int64)
	// SetRefreshTime Set refresh time.
	SetRefreshTime(refreshTime int64)
	// SetTokenCtxKey Set the key of the token for context transfer.
	SetTokenCtxKey(tokenCtxKey string)
	// SetSecret Set secret key.
	SetSecret(secret string)
	// SetPublicKey Set public key.
	SetPublicKey(publicKey string) error
	// SetPrivateKey Set private key.
	SetPrivateKey(privateKey string) error
	// ReadPublicKey Read public key from file.
	ReadPublicKey(file string) error
	// ReadPrivateKey Read private key from file.
	ReadPrivateKey(file string) error
	// Middleware A jwt auth middleware.
	Middleware(r *http.Request) (*http.Request, error)
	// GenerateToken Generate a token.
	GenerateToken(payload map[string]interface{}) (*Token, error)
	// RefreshToken Refresh a token.
	RefreshToken(tokenStr string) (*Token, error)
	// LookupToken Look up token from request.
	LookupToken(r *http.Request) (string, error)
	// ParseToken Parse token into map.
	ParseToken(tokenStr string) (jwt.MapClaims, error)
	// GetCtxValue Get value from request's context.
	GetCtxValue(r *http.Request, key string) interface{}
}

type Options struct {
	Realm          string
	Algorithm      string
	Secret         string
	ExpireTime     int64
	RefreshTime    int64
	TokenLookup    string
	TokenCtxKey    string
	PublicKey      string
	PrivateKey     string
	PublicKeyFile  string
	PrivateKeyFile string
}

type defaultJwt struct {
	realm       string
	algorithm   string
	Secret      string
	expireTime  time.Duration
	refreshTime time.Duration
	tokenCtxKey string
	tokenLookup [][2]string
	publicKey   *rsa.PublicKey
	privateKey  *rsa.PrivateKey
	secretKey   []byte
	err         error
}

type Token struct {
	Type      string `json:"type"`
	Token     string `json:"token"`
	ExpireAt  string `json:"expire_at"`
	InvalidAt string `json:"invalid_at"`
}

const (
	jwtRealm         = "rea"
	jwtAudience      = "aud"
	jwtExpire        = "exp"
	jwtId            = "jti"
	jwtIssueAt       = "iat"
	jwtIssuer        = "iss"
	jwtNotBefore     = "nbf"
	jwtSubject       = "sub"
	jwtExclusiveCode = "esc"
	noDetailReason   = "no detail reason"
)

const (
	tokenLookupHeader      = "header"
	tokenLookupQuery       = "query"
	tokenLookupCookie      = "cookie"
	tokenLookupForm        = "form"
	tokenLookupFieldHeader = "Authorization"
	tokenHeaderName        = "Bearer"
	
	HS256 = "HS256"
	HS512 = "HS512"
	RS256 = "RS256"
	RS384 = "RS384"
	RS512 = "RS512"
)

func NewJwt(opt *Options) (JWT, error) {
	j := new(defaultJwt)
	j.realm
	j.setAlgorithm(opt.Algorithm)
	j.setTokenLookup(opt.TokenLookup)
	j.SetExpireTime(opt.ExpireTime)
	j.SetRefreshTime(opt.RefreshTime)
	j.setSecretKey(opt.Secret)
	j.setTokenCtxKey(opt.TokenCtxKey)
	
	if j.isRsaAlgorithm() {
	
	}
	
	j.setPublicKey(opt.PublicKey)
	j.setPrivateKey(opt.PrivateKey)
	
	return j
}

// SetExpireTime Set expiration time.
func (j *defaultJwt) SetExpireTime(expireTime int64) {
	if expireTime > 0 {
		j.expireTime = time.Duration(expireTime) * time.Second
	} else {
		j.expireTime = time.Hour
	}
}

// SetRefreshTime Set refresh time.
func (j *defaultJwt) SetRefreshTime(refreshTime int64) {
	if refreshTime > 0 {
		j.refreshTime = time.Duration(refreshTime) * time.Second
	} else {
		j.refreshTime = 5 * time.Hour
	}
}

// Middleware A jwt auth middleware.
func (j *defaultJwt) Middleware(r *http.Request) (*http.Request, error) {
	token := j.LookupToken(r)
	
	claims, err := j.ParseToken(token)
	if err != nil {
		return nil, err
	}
	
	ctx := r.Context()
	for k, v := range claims {
		switch k {
		case jwtAudience, jwtExpire, jwtId, jwtIssueAt, jwtIssuer, jwtNotBefore, jwtSubject:
			// ignore the standard claims
		default:
			ctx = context.WithValue(ctx, k, v)
		}
	}
	
	if j.tokenCtxKey != "" {
		ctx = context.WithValue(ctx, j.tokenCtxKey, token)
	}
	
	return r.WithContext(ctx), nil
}

// GenerateToken Generate a token.
func (j *defaultJwt) GenerateToken(payload map[string]interface{}) (*Token, error) {
	expire := time.Now().Add(j.expireTime)
	claims := make(jwt.MapClaims)
	claims[jwtIssueAt] = time.Now().Unix()
	claims[jwtExpire] = expire.Unix()
	claims[jwtExclusiveCode] = time.Now().UnixNano()
	for k, v := range payload {
		switch k {
		case jwtIssueAt, jwtExpire, jwtExclusiveCode:
			// ignore the standard claims
		default:
			claims[k] = v
		}
	}
	
	token, err := j.signedToken(claims)
	if err != nil {
		return nil, err
	}
	
	return &Token{
		Type:      tokenHeaderName,
		Token:     token,
		ExpireAt:  expire.Format(time.RFC3339),
		InvalidAt: time.Unix(claims[jwtIssueAt].(int64), 0).Add(j.refreshTime).Format(time.RFC3339),
	}, nil
}

// RefreshToken Refresh a token.
func (j *defaultJwt) RefreshToken(tokenStr string) (*Token, error) {
	var (
		err       error
		claims    jwt.MapClaims
		newClaims jwt.MapClaims
	)
	
	claims, err = j.ParseToken(tokenStr)
	if err != nil && err != ErrExpiredToken {
		return nil, err
	}
	
	newClaims = make(jwt.MapClaims)
	for k, v := range claims {
		newClaims[k] = v
	}
	
	expire := time.Now().Add(j.expireTime)
	
	newClaims[jwtExpire] = expire.Unix()
	
	tokenStr, err = j.signedToken(newClaims)
	if err != nil {
		return nil, err
	}
	
	return &Token{
		Type:      tokenHeaderName,
		Token:     tokenStr,
		ExpireAt:  expire.Format(time.RFC3339),
		InvalidAt: time.Unix(int64(newClaims[jwtIssueAt].(float64)), 0).Add(j.refreshTime).Format(time.RFC3339),
	}, nil
}

// ParseToken Parse token into map.
func (j *defaultJwt) ParseToken(tokenStr string) (jwt.MapClaims, error) {
	token, err := j.parsedToken(tokenStr)
	if err != nil {
		if validationErr, ok := err.(*jwt.ValidationError); !ok || validationErr.Errors != jwt.ValidationErrorExpired {
			return nil, ErrInvalidToken
		}
	}
	
	if token == nil {
		return nil, ErrEmptyToken
	}
	
	claims := token.Claims.(jwt.MapClaims)
	
	if iat, ok := claims[jwtIssueAt]; !ok {
		return nil, ErrInvalidToken
	} else if int64(iat.(float64)) < time.Now().Add(-j.refreshTime).Unix() {
		return nil, ErrInvalidToken
	}
	
	if exp, ok := claims[jwtExpire]; !ok {
		return nil, ErrInvalidToken
	} else if int64(exp.(float64)) < time.Now().Unix() {
		return claims, ErrExpiredToken
	}
	
	return claims, nil
}

// GetCtxValue Get value from request's context.
func (j *defaultJwt) GetCtxValue(r *http.Request, key string) interface{} {
	return r.Context().Value(key)
}

// LookupToken Look up token from request.
func (j *defaultJwt) LookupToken(r *http.Request) (token string) {
	for _, item := range j.tokenLookup {
		if len(token) > 0 {
			break
		}
		switch item[0] {
		case tokenLookupHeader:
			token = j.lookupTokenFromHeader(r, item[1])
		case tokenLookupQuery:
			token = j.lookupTokenFromQuery(r, item[1])
		case tokenLookupCookie:
			token = j.lookupTokenFromCookie(r, item[1])
		case tokenLookupForm:
			token = j.lookupTokenFromForm(r, item[1])
		}
	}
	
	return
}

// lookupTokenFromHeader Get token from headers of request.
func (j *defaultJwt) lookupTokenFromHeader(r *http.Request, key string) string {
	parts := strings.SplitN(r.Header.Get(key), " ", 2)
	if len(parts) != 2 || parts[0] != tokenHeaderName {
		return ""
	}
	
	return parts[1]
}

// lookupTokenFromQuery Get token from queries of request.
func (j *defaultJwt) lookupTokenFromQuery(r *http.Request, key string) string {
	return r.URL.Query().Get(key)
}

// lookupTokenFromCookie Get token from cookies of request.
func (j *defaultJwt) lookupTokenFromCookie(r *http.Request, key string) string {
	cookie, _ := r.Cookie(key)
	return cookie.String()
}

// lookupTokenFromForm Get token from form of request.
func (j *defaultJwt) lookupTokenFromForm(r *http.Request, key string) string {
	return r.Form.Get(key)
}

// Parse the token
func (j *defaultJwt) parsedToken(tokenStr string) (*jwt.Token, error) {
	return jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if jwt.GetSigningMethod(j.algorithm) != t.Method {
			return nil, ErrInvalidSigningAlgorithm
		}
		
		if j.isRsaAlgorithm() {
			return j.publicKey, nil
		} else {
			return j.secretKey, nil
		}
	})
}

// signedToken Sign the token.
func (j *defaultJwt) signedToken(claims jwt.MapClaims) (string, error) {
	var (
		err      error
		tokenStr string
		token    = jwt.New(jwt.GetSigningMethod(j.algorithm))
	)
	
	token.Claims = claims
	
	if j.isRsaAlgorithm() {
		tokenStr, err = token.SignedString(j.privateKey)
	} else {
		tokenStr, err = token.SignedString(j.secretKey)
	}
	
	if err != nil {
		return "", ErrFailedTokenCreation
	}
	
	return tokenStr, nil
}

// Check which signature algorithm is used
func (j *defaultJwt) isRsaAlgorithm() bool {
	switch j.algorithm {
	case RS256, RS384, RS512:
		return true
	}
	return false
}

func ()() {

}

// Set encryption algorithm
func (j *defaultJwt) setAlgorithm(algorithm string) {
	switch algorithm {
	case RS256, RS384, RS512, HS256, HS512:
		j.algorithm = algorithm
	default:
		j.algorithm = HS256
	}
}

// SetTokenLookup Set the token search location.
func (j *defaultJwt) setTokenLookup(tokenLookup string) {
	j.tokenLookup = make([][2]string, 0)
	
	for _, method := range strings.Split(tokenLookup, ",") {
		parts := strings.Split(strings.TrimSpace(method), ":")
		k := strings.TrimSpace(parts[0])
		v := strings.TrimSpace(parts[1])
		switch k {
		case tokenLookupHeader, tokenLookupQuery, tokenLookupCookie, tokenLookupForm:
			j.tokenLookup = append(j.tokenLookup, [2]string{k, v})
		}
	}
	
	if len(j.tokenLookup) == 0 {
		j.tokenLookup = append(j.tokenLookup, [2]string{tokenLookupHeader, tokenLookupFieldHeader})
	}
}

// Set the key of the token for context transfer.
func (j *defaultJwt) setTokenCtxKey(tokenCtxKey string) {
	j.tokenCtxKey = tokenCtxKey
}

// Set secret key.
func (j *defaultJwt) setSecretKey(secretKey string) {
	j.secretKey = stringToBytes(secretKey)
}

//
func (j *defaultJwt) setRasKey(publicKey, privateKey string) (err error) {
	if err = j.setPublicKey(publicKey); err != nil {
		return
	}
	
	if err = j.setPrivateKey(privateKey); err != nil {
		return
	}
	
	return
}

// Set public key.
// allow the public key file path or the public key.
func (j *defaultJwt) setPublicKey(publicKey string) (err error) {
	if publicKey == "" {
		return errInvalidPublicKey
	}
	
	var key []byte
	
	if fileInfo, err := os.Stat(publicKey); err != nil {
		key = stringToBytes(publicKey)
	} else {
		if fileInfo.Size() == 0 {
			return errInvalidPublicKey
		}
		
		if key, err = ioutil.ReadFile(publicKey); err != nil {
			return
		}
	}
	
	if j.publicKey, err = jwt.ParseRSAPublicKeyFromPEM(key); err != nil {
		return
	}
	
	return
}

// Set private key.
// allow the private key file path or the private key.
func (j *defaultJwt) setPrivateKey(privateKey string) (err error) {
	if privateKey == "" {
		return errInvalidPrivateKey
	}
	
	var key []byte
	
	if fileInfo, err := os.Stat(privateKey); err != nil {
		key = stringToBytes(privateKey)
	} else {
		if fileInfo.Size() == 0 {
			return errInvalidPrivateKey
		}
		
		if key, err = ioutil.ReadFile(privateKey); err != nil {
			return
		}
	}
	
	if j.privateKey, err = jwt.ParseRSAPrivateKeyFromPEM(key); err != nil {
		return
	}
	
	return
}

func stringToBytes(str string) []byte {
	return *(*[]byte)(unsafe.Pointer(&str))
}

func bytesToString(bytes []byte) string {
	return *(*string)(unsafe.Pointer(&bytes))
}
