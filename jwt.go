package jwt

import (
	"context"
	"crypto/rsa"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
	
	"github.com/dgrijalva/jwt-go"
)

type JWT interface {
	// SetOptions Set options for jwt.
	SetOptions(opt *Options)
	// SetRealm Set realm for jwt.
	SetRealm(realm string)
	// SetTokenLookup Set the token search location.
	SetTokenLookup(tokenLookup string)
	// SetAlgorithm Set encryption algorithm
	SetAlgorithm(algorithm string)
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
	tokenLookupHeader = "header"
	tokenLookupQuery  = "query"
	tokenLookupCookie = "cookie"
	tokenLookupForm   = "form"
	tokenHeaderName   = "Bearer"
)

func NewJwt(opt *Options) JWT {
	j := &defaultJwt{}
	j.SetOptions(opt)
	return j
}

// SetOptions Set options for jwt.
func (j *defaultJwt) SetOptions(opt *Options) {
	if opt != nil {
		j.SetRealm(opt.Realm)
		j.SetAlgorithm(opt.Algorithm)
		j.SetTokenLookup(opt.TokenLookup)
		j.SetExpireTime(opt.ExpireTime)
		j.SetRefreshTime(opt.RefreshTime)
		j.SetSecret(opt.Secret)
		j.SetTokenCtxKey(opt.TokenCtxKey)
		
		if opt.PublicKey != "" {
			_ = j.SetPublicKey(opt.PublicKey)
		}
		
		if opt.PrivateKey != "" {
			_ = j.SetPrivateKey(opt.PrivateKey)
		}
		
		if opt.PublicKeyFile != "" {
			_ = j.ReadPublicKey(opt.PublicKeyFile)
		}
		
		if opt.PrivateKeyFile != "" {
			_ = j.ReadPrivateKey(opt.PrivateKeyFile)
		}
	}
}

// SetRealm Set realm for jwt.
func (j *defaultJwt) SetRealm(realm string) {
	j.realm = realm
}

// SetTokenLookup Set the token search location.
func (j *defaultJwt) SetTokenLookup(tokenLookup string) {
	j.tokenLookup = make([][2]string, 0)
	
	if tokenLookup == "" {
		tokenLookup = "header:Authorization"
	}
	
	for _, method := range strings.Split(tokenLookup, ",") {
		parts := strings.Split(strings.TrimSpace(method), ":")
		k := strings.TrimSpace(parts[0])
		v := strings.TrimSpace(parts[1])
		switch k {
		case tokenLookupHeader, tokenLookupQuery, tokenLookupCookie, tokenLookupForm:
			j.tokenLookup = append(j.tokenLookup, [2]string{k, v})
		}
	}
}

// SetAlgorithm Set encryption algorithm
func (j *defaultJwt) SetAlgorithm(algorithm string) {
	if algorithm != "" {
		j.algorithm = algorithm
	} else {
		j.algorithm = "HS256"
	}
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

// SetTokenCtxKey Set the key of the token for context transfer.
func (j *defaultJwt) SetTokenCtxKey(tokenCtxKey string) {
	j.tokenCtxKey = tokenCtxKey
}

// SetSecret Set secret key.
func (j *defaultJwt) SetSecret(secret string) {
	j.secretKey = []byte(secret)
}

// SetPublicKey Set public key.
func (j *defaultJwt) SetPublicKey(publicKey string) error {
	if key, err := jwt.ParseRSAPublicKeyFromPEM([]byte(publicKey)); err != nil {
		return ErrInvalidPublicKey
	} else {
		j.publicKey = key
		
		return nil
	}
}

// SetPrivateKey Set private key.
func (j *defaultJwt) SetPrivateKey(privateKey string) error {
	if key, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(privateKey)); err != nil {
		return ErrInvalidPrivateKey
	} else {
		j.privateKey = key
		
		return nil
	}
}

// ReadPublicKey Read public key from file.
func (j *defaultJwt) ReadPublicKey(file string) error {
	if data, err := ioutil.ReadFile(file); err != nil {
		return ErrNoPublicKeyFile
	} else {
		return j.SetPublicKey(string(data))
	}
}

// ReadPrivateKey Read private key from file
func (j *defaultJwt) ReadPrivateKey(file string) error {
	if data, err := ioutil.ReadFile(file); err != nil {
		return ErrNoPrivateKeyFile
	} else {
		return j.SetPrivateKey(string(data))
	}
}

// Middleware A jwt auth middleware.
func (j *defaultJwt) Middleware(r *http.Request) (*http.Request, error) {
	tokenStr, err := j.LookupToken(r)
	if err != nil {
		return nil, err
	}
	
	claims, err := j.ParseToken(tokenStr)
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
		ctx = context.WithValue(ctx, j.tokenCtxKey, tokenStr)
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
		if k != jwtIssueAt && k != jwtExpire && k != jwtExclusiveCode {
			claims[k] = v
		}
	}
	
	tokenStr, err := j.signedToken(claims)
	if err != nil {
		return nil, err
	}
	
	return &Token{
		Type:      tokenHeaderName,
		Token:     tokenStr,
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
func (j *defaultJwt) LookupToken(r *http.Request) (string, error) {
	var (
		err      error
		tokenStr string
	)
	
	for _, item := range j.tokenLookup {
		if len(tokenStr) > 0 {
			break
		}
		
		switch item[0] {
		case tokenLookupHeader:
			tokenStr, err = j.lookupTokenFromHeader(r, item[1])
		case tokenLookupQuery:
			tokenStr, err = j.lookupTokenFromQuery(r, item[1])
		case tokenLookupCookie:
			tokenStr, err = j.lookupTokenFromCookie(r, item[1])
		case tokenLookupForm:
			tokenStr, err = j.lookupTokenFromForm(r, item[1])
		}
	}
	if err != nil {
		return "", err
	}
	
	return tokenStr, err
}

// lookupTokenFromHeader Get token from headers of request.
func (j *defaultJwt) lookupTokenFromHeader(r *http.Request, key string) (string, error) {
	authHeader := r.Header.Get(key)
	
	if authHeader == "" {
		return "", ErrEmptyAuthHeader
	}
	
	parts := strings.SplitN(authHeader, " ", 2)
	if !(len(parts) == 2 && parts[0] == tokenHeaderName) {
		return "", ErrInvalidAuthHeader
	}
	
	return parts[1], nil
}

// lookupTokenFromQuery Get token from queries of request.
func (j *defaultJwt) lookupTokenFromQuery(r *http.Request, key string) (string, error) {
	tokenStr := r.URL.Query().Get(key)
	
	if tokenStr == "" {
		return "", ErrEmptyQueryToken
	}
	
	return tokenStr, nil
}

// lookupTokenFromCookie Get token from cookies of request.
func (j *defaultJwt) lookupTokenFromCookie(r *http.Request, key string) (string, error) {
	cookie, err := r.Cookie(key)
	if err != nil {
		return "", ErrEmptyCookieToken
	}
	
	tokenStr := cookie.String()
	
	if tokenStr == "" {
		return "", ErrEmptyCookieToken
	}
	
	return tokenStr, nil
}

// lookupTokenFromForm Get token from form of request.
func (j *defaultJwt) lookupTokenFromForm(r *http.Request, key string) (string, error) {
	tokenStr := r.Form.Get(key)
	
	if tokenStr == "" {
		return "", ErrEmptyParamToken
	}
	
	return tokenStr, nil
}

// parsedToken Parse the token
func (j *defaultJwt) parsedToken(tokenStr string) (*jwt.Token, error) {
	return jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if jwt.GetSigningMethod(j.algorithm) != t.Method {
			return nil, ErrInvalidSigningAlgorithm
		}
		
		if j.isRsaAlgo() {
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
	
	if j.isRsaAlgo() {
		tokenStr, err = token.SignedString(j.privateKey)
	} else {
		tokenStr, err = token.SignedString(j.secretKey)
	}
	
	if err != nil {
		return "", ErrFailedTokenCreation
	}
	
	return tokenStr, nil
}

// isRsaAlgo Check which signature algorithm is used
func (j *defaultJwt) isRsaAlgo() bool {
	switch j.algorithm {
	case "RS256", "RS512", "RS384":
		return true
	}
	return false
}
