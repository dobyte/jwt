package jwt

import (
	"crypto/rsa"
	"github.com/dgrijalva/jwt-go"
	"github.com/gogf/gf/net/ghttp"
	"github.com/gogf/gf/os/gcache"
	"github.com/gogf/gf/util/gconv"
	"github.com/gogf/gf/util/guid"
	"io/ioutil"
	"strings"
	"time"
)

type Jwt struct {
	Realm          string
	Algorithm      string
	Secret         string
	ExpireTime     time.Duration
	RefreshTime    time.Duration
	IsUnique       bool
	IdentityKey    string
	TokenLookup    string
	TokenHeadName  string
	PublicKeyFile  string
	PrivateKeyFile string
	publicKey      *rsa.PublicKey
	privateKey     *rsa.PrivateKey
	key            []byte
}

type Token struct {
	Token  string
	Expire string
	Type   string
}

// Create a jwt
func NewJwt(j *Jwt) (*Jwt, error) {
	if err := j.init(); err != nil {
		return nil, err
	}

	return j, nil
}

// Init default value
func (j *Jwt) init() error {
	if j.TokenLookup == "" {
		j.TokenLookup = "header:Authorization"
	}

	if j.Algorithm == "" {
		j.Algorithm = "HS256"
	}

	if j.ExpireTime == 0 {
		j.ExpireTime = time.Hour
	}

	j.TokenHeadName = strings.TrimSpace(j.TokenHeadName)
	if len(j.TokenHeadName) == 0 {
		j.TokenHeadName = "Bearer"
	}

	if j.usingRsaKeyAlgo() {
		return j.readRsaKeys()
	}

	j.key = []byte(j.Secret)
	if j.key == nil {
		return ErrMissingSecretKey
	}

	return nil
}

// Generate a token
func (j *Jwt) GenerateToken(data interface{}) (*Token, error) {
	token := jwt.New(jwt.GetSigningMethod(j.Algorithm))

	claims := token.Claims.(jwt.MapClaims)

	for key, value := range j.handlePayload(data) {
		claims[key] = value
	}

	expire := time.Now().Add(j.ExpireTime)

	claims["exp"] = expire.Unix()

	claims["orig_iat"] = time.Now().Unix()

	claims["uic"] = guid.S()

	tokenString, err := j.signedString(token)

	if err != nil {
		return nil, ErrFailedTokenCreation
	}

	if j.IsUnique {
		j.SetUniqueIdentificationCode(claims)
	}

	return &Token{
		Token:  tokenString,
		Expire: expire.Format(time.RFC3339),
		Type:   j.TokenHeadName,
	}, nil
}

// Refresh a token
func (j *Jwt) RefreshToken(request *ghttp.Request) (*Token, error) {
	claims, err := j.CheckIfTokenExpire(request)

	if err != nil {
		return nil, err
	}

	if err := j.checkUniqueIdentificationCode(claims); err != nil {
		return nil, err
	}

	newToken := jwt.New(jwt.GetSigningMethod(j.Algorithm))

	newClaims := newToken.Claims.(jwt.MapClaims)

	for key := range claims {
		newClaims[key] = claims[key]
	}

	expire := time.Now().Add(j.ExpireTime)

	newClaims["exp"] = expire.Unix()

	newClaims["orig_iat"] = time.Now().Unix()

	newClaims["uic"] = guid.S()

	tokenString, err := j.signedString(newToken)

	if err != nil {
		return nil, ErrFailedTokenCreation
	}

	if j.IsUnique {
		j.SetUniqueIdentificationCode(newClaims)
	}

	return &Token{
		Token:  tokenString,
		Expire: expire.Format(time.RFC3339),
		Type:   j.TokenHeadName,
	}, nil
}

// Destroy a token
func (j *Jwt) DestroyToken(request *ghttp.Request) error {
	if j.IsUnique {
		if claims, err := j.GetClaims(request); err != nil {
			return err
		} else {
			if claims["uic"] == j.GetUniqueIdentificationCode(claims[j.IdentityKey]) {
				return j.DelUniqueIdentificationCode(claims[j.IdentityKey])
			}
		}
	}

	return nil
}

// Check whether the token has expired
func (j *Jwt) CheckIfTokenExpire(r *ghttp.Request) (jwt.MapClaims, error) {
	token, err := j.parseToken(r)

	if err != nil {
		validationErr, ok := err.(*jwt.ValidationError)

		if !ok || validationErr.Errors != jwt.ValidationErrorExpired {
			return nil, ErrInvalidToken
		}
	}

	if token == nil {
		return nil, ErrEmptyToken
	}

	claims := token.Claims.(jwt.MapClaims)

	origIat := int64(claims["orig_iat"].(float64))

	if origIat < time.Now().Add(-j.RefreshTime).Unix() {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

// Parse a token
func (j *Jwt) parseToken(request *ghttp.Request) (*jwt.Token, error) {
	var (
		tokenString string
		err         error
	)

	for _, method := range strings.Split(j.TokenLookup, ",") {
		if len(tokenString) > 0 {
			break
		}

		parts := strings.Split(strings.TrimSpace(method), ":")
		k := strings.TrimSpace(parts[0])
		v := strings.TrimSpace(parts[1])

		switch k {
		case "header":
			tokenString, err = j.getTokenFromHeader(request, v)
		case "query":
			tokenString, err = j.getTokenFromQuery(request, v)
		case "cookie":
			tokenString, err = j.getTokenFromCookie(request, v)
		case "param":
			tokenString, err = j.getTokenFromParam(request, v)
		}
	}

	if err != nil {
		return nil, err
	}

	return jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		if jwt.GetSigningMethod(j.Algorithm) != t.Method {
			return nil, ErrInvalidSigningAlgorithm
		}

		if j.usingRsaKeyAlgo() {
			return j.publicKey, nil
		}

		request.SetParam("JWT_TOKEN", tokenString)

		return j.key, nil
	})
}

// Provide a middleware for go-frame
func (j *Jwt) Middleware(request *ghttp.Request) error {
	var (
		err    error
		claims jwt.MapClaims
	)

	claims, err = j.GetClaimsFromRequest(request)
	if err != nil {
		return err
	}

	if claims["exp"] == nil {
		return ErrMissingExpField
	}

	if _, ok := claims["exp"].(float64); !ok {
		return ErrWrongFormatOfExp
	}

	if int64(claims["exp"].(float64)) < time.Now().Unix() {
		return ErrExpiredToken
	}

	if err = j.checkUniqueIdentificationCode(claims); err != nil {
		return err
	}

	j.SetClaims(request, claims)

	return nil
}

// Get claims params from request
func (j *Jwt) GetClaimsFromRequest(request *ghttp.Request) (jwt.MapClaims, error) {
	token, err := j.parseToken(request)

	if err != nil {
		return nil, ErrInvalidToken
	}

	claims := jwt.MapClaims{}
	for key, value := range token.Claims.(jwt.MapClaims) {
		claims[key] = value
	}

	return claims, nil
}

// Get identity from request
func (j *Jwt) GetIdentity(request *ghttp.Request) interface{} {
	if claims, err := j.GetClaims(request); err != nil {
		return nil
	} else {
		return claims[j.IdentityKey]
	}
}

// Get claims params from request
func (j *Jwt) GetClaims(request *ghttp.Request) (jwt.MapClaims, error) {
	claims := request.GetParam("JWT_PAYLOAD")

	if claims != nil {
		return claims.(jwt.MapClaims), nil
	}

	return j.GetClaimsFromRequest(request)
}

// Set claims params to request
func (j *Jwt) SetClaims(request *ghttp.Request, claims jwt.MapClaims) {
	request.SetParam("JWT_PAYLOAD", claims)
}

// Read public key and private key
func (j *Jwt) readRsaKeys() error {
	if err := j.readPrivateKey(); err != nil {
		return err
	}

	if err := j.readPublicKey(); err != nil {
		return err
	}

	return nil
}

// Read private key from file
func (j *Jwt) readPrivateKey() error {
	keyData, err := ioutil.ReadFile(j.PrivateKeyFile)

	if err != nil {
		return ErrNoPrivateKeyFile
	}

	key, err := jwt.ParseRSAPrivateKeyFromPEM(keyData)

	if err != nil {
		return ErrInvalidPrivateKey
	}

	j.privateKey = key

	return nil
}

// Read public key from file
func (j *Jwt) readPublicKey() error {
	keyData, err := ioutil.ReadFile(j.PublicKeyFile)

	if err != nil {
		return ErrNoPublicKeyFile
	}

	key, err := jwt.ParseRSAPublicKeyFromPEM(keyData)

	if err != nil {
		return ErrInvalidPublicKey
	}

	j.publicKey = key

	return nil
}

// Sign token
func (j *Jwt) signedString(token *jwt.Token) (string, error) {
	var tokenString string

	var err error

	if j.usingRsaKeyAlgo() {
		tokenString, err = token.SignedString(j.privateKey)
	} else {
		tokenString, err = token.SignedString(j.key)
	}

	if err != nil {
		return "", ErrFailedTokenCreation
	}

	return tokenString, nil
}

// Check which signature algorithm is used
func (j *Jwt) usingRsaKeyAlgo() bool {
	switch j.Algorithm {
	case "RS256", "RS512", "RS384":
		return true
	}
	return false
}

// Copy value from data package to claims
func (j *Jwt) handlePayload(data interface{}) jwt.MapClaims {
	claims := jwt.MapClaims{}

	params := data.(map[string]interface{})

	if len(params) > 0 {
		for k, v := range params {
			claims[k] = v
		}
	}

	return claims
}

// Get a token from header of request
func (j *Jwt) getTokenFromHeader(request *ghttp.Request, key string) (string, error) {
	authHeader := request.Header.Get(key)

	if authHeader == "" {
		return "", ErrEmptyAuthHeader
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if !(len(parts) == 2 && parts[0] == j.TokenHeadName) {
		return "", ErrInvalidAuthHeader
	}

	return parts[1], nil
}

// Get a token from query of request
func (j *Jwt) getTokenFromQuery(request *ghttp.Request, key string) (string, error) {
	token := request.GetString(key)

	if token == "" {
		return "", ErrEmptyQueryToken
	}

	return token, nil
}

// Get a token from cookie of request
func (j *Jwt) getTokenFromCookie(request *ghttp.Request, key string) (string, error) {
	cookie := request.Cookie.Get(key)

	if cookie == "" {
		return "", ErrEmptyCookieToken
	}

	return cookie, nil
}

// Get a token from param of request
func (j *Jwt) getTokenFromParam(request *ghttp.Request, key string) (string, error) {
	token := request.GetString(key)

	if token == "" {
		return "", ErrEmptyParamToken
	}

	return token, nil
}

// Check unique identification code
func (j *Jwt) checkUniqueIdentificationCode(claims jwt.MapClaims) error {
	if j.IsUnique {
		if uic := j.GetUniqueIdentificationCode(claims[j.IdentityKey]); uic != "" {
			if uic != claims["uic"] {
				return ErrAuthorizeElsewhere
			}
		} else {
			return ErrInvalidToken
		}
	}

	return nil
}

// Set unique identification code
func (j *Jwt) SetUniqueIdentificationCode(claims jwt.MapClaims) {
	gcache.Set("jwt:"+j.Realm+":"+gconv.String(claims[j.IdentityKey]), claims["uic"], j.ExpireTime)
}

// Get unique identification code
func (j *Jwt) GetUniqueIdentificationCode(identity interface{}) string {
	if uic, err := gcache.Get("jwt:" + j.Realm + ":" + gconv.String(identity)); err != nil {
		return ""
	} else {
		return gconv.String(uic)
	}
}

// Delete unique identification code
func (j *Jwt) DelUniqueIdentificationCode(identity interface{}) error {
	if _, err := gcache.Remove("jwt:" + j.Realm + ":" + gconv.String(identity)); err != nil {
		return ErrFailedTokenDestroy
	} else {
		return nil
	}
}
