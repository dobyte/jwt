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
    
    jwts "github.com/dgrijalva/jwt-go"
)

type (
    Algorithm string
    
    Cache interface {
    }
    
    JWT interface {
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
)

type Options struct {
    //
    Realm          string
    Algorithm      string
    SecretKey      string
    RefreshTime    int64
    ExpirationTime int64
    TokenLookup    string
    TokenCtxKey    string
    
    // public key file or public key.
    PublicKey string
    
    // private key file or private key.
    PrivateKey string
}

type jwt struct {
    realm          string
    algorithm      string
    expirationTime time.Duration
    refreshTime    time.Duration
    tokenCtxKey    string
    tokenLookup    [][2]string
    publicKey      *rsa.PublicKey
    privateKey     *rsa.PrivateKey
    secretKey      []byte
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
    
    HS256                 = "HS256"
    HS512                 = "HS512"
    HS384                 = "HS384"
    RS256                 = "RS256"
    RS384                 = "RS384"
    RS512                 = "RS512"
    ES256                 = "ES256"
    ES384                 = "ES384"
    ES512                 = "ES512"
    defaultAlgorithm      = HS256
    defaultTokenCtxKey    = "token"
    defaultExpirationTime = time.Hour
    defaultRefreshTime    = 5 * time.Hour
)

func NewJwt(opt *Options) (JWT, error) {
    j := new(jwt)
    j.setRealm(opt.Realm)
    j.setTokenCtxKey(opt.TokenCtxKey)
    j.setTokenLookup(opt.TokenLookup)
    j.setExpirationTime(opt.ExpirationTime)
    j.setRefreshTime(opt.RefreshTime)
    
    var err error
    
    if err = j.setAlgorithm(opt.Algorithm); err != nil {
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

// Middleware A jwt auth middleware.
func (j *jwt) Middleware(r *http.Request) (*http.Request, error) {
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

// GenerateToken generates and returns a new token object.
func (j *jwt) GenerateToken(payload map[string]interface{}) (*Token, error) {
    now := time.Now()
    expire := now.Add(j.expirationTime)
    claims := make(jwts.MapClaims)
    claims[jwtIssueAt] = now.Unix()
    claims[jwtExpire] = expire.Unix()
    claims[jwtExclusiveCode] = now.UnixNano()
    for k, v := range payload {
        switch k {
        case jwtIssueAt, jwtExpire, jwtExclusiveCode:
            // ignore the standard claims
        default:
            claims[k] = v
        }
    }
    
    token, err := j.signingToken(claims)
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

// RefreshToken generates and returns a new token object depend on old token.
//
func (j *jwt) RefreshToken(token string) (*Token, error) {
    var (
        err       error
        claims    jwts.MapClaims
        newClaims jwts.MapClaims
    )
    
    claims, err = j.ParseToken(token)
    if err != nil && err != ErrExpiredToken {
        return nil, err
    }
    
    newClaims = make(jwts.MapClaims)
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
func (j *jwt) ParseToken(tokenStr string) (jwts.MapClaims, error) {
    token, err := j.parsedToken(tokenStr)
    if err != nil {
        if validationErr, ok := err.(*jwts.ValidationError); !ok || validationErr.Errors != jwts.ValidationErrorExpired {
            return nil, ErrInvalidToken
        }
    }
    
    if token == nil {
        return nil, ErrEmptyToken
    }
    
    claims := token.Claims.(jwts.MapClaims)
    
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
func (j *jwt) GetCtxValue(r *http.Request, key string) interface{} {
    return r.Context().Value(key)
}

// LookupToken Look up token from request.
func (j *jwt) LookupToken(r *http.Request) (token string) {
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
func (j *jwt) lookupTokenFromHeader(r *http.Request, key string) string {
    parts := strings.SplitN(r.Header.Get(key), " ", 2)
    if len(parts) != 2 || parts[0] != tokenHeaderName {
        return ""
    }
    
    return parts[1]
}

// lookupTokenFromQuery Get token from queries of request.
func (j *jwt) lookupTokenFromQuery(r *http.Request, key string) string {
    return r.URL.Query().Get(key)
}

// lookupTokenFromCookie Get token from cookies of request.
func (j *jwt) lookupTokenFromCookie(r *http.Request, key string) string {
    cookie, _ := r.Cookie(key)
    return cookie.String()
}

// lookupTokenFromForm Get token from form of request.
func (j *jwt) lookupTokenFromForm(r *http.Request, key string) string {
    return r.Form.Get(key)
}

// Parse the token
func (j *jwt) parsingToken(tokenStr string) (*jwts.Token, error) {
    return jwts.Parse(tokenStr, func(t *jwts.Token) (interface{}, error) {
        if jwts.GetSigningMethod(j.algorithm) != t.Method {
            return nil, ErrInvalidSigningAlgorithm
        }
        
        if j.isRsaAlgorithm() {
            return j.publicKey, nil
        } else {
            return j.secretKey, nil
        }
    })
}

// signings the claims and returns a token.
func (j *jwt) signingToken(claims jwts.MapClaims) (token string, err error) {
    jt := jwts.New(jwts.GetSigningMethod(j.algorithm))
    jt.Claims = claims
    
    if j.isHMAC() {
        token, err = jt.SignedString(j.secretKey)
    } else {
        token, err = jt.SignedString(j.privateKey)
    }
    if err != nil {
        return
    }
    
    return
}

func (j *jwt) isHMAC() bool {
    switch j.algorithm {
    case HS256, HS384, HS512:
        return true
    }
    return false
}

//
func (j *jwt) isRSA() bool {
    switch j.algorithm {
    case RS256, RS384, RS512:
        return true
    }
    return false
}

//
func (j *jwt) isECDSA() bool {
    switch j.algorithm {
    case RS256, RS384, RS512:
        return true
    }
    return false
}

// Check which signature algorithm is used
func (j *jwt) isRsaAlgorithm() bool {
    switch j.algorithm {
    case RS256, RS384, RS512:
        return true
    }
    return false
}

// Set signing algorithms.
// Support multiple signing algorithms such as HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384 and ES512
func (j *jwt) setAlgorithm(algorithm string) error {
    switch algorithm {
    case HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512:
        j.algorithm = algorithm
    case "":
        j.algorithm = defaultAlgorithm
    default:
        return errInvalidSigningAlgorithm
    }
    
    return nil
}

// SetTokenLookup Set the token search location.
func (j *jwt) setTokenLookup(tokenLookup string) {
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

func (j *jwt) setRealm(realm string) {
    j.realm = realm
}

// Set the key of the token for context transfer.
func (j *jwt) setTokenCtxKey(tokenCtxKey string) {
    if tokenCtxKey != "" {
        j.tokenCtxKey = tokenCtxKey
    } else {
        j.tokenCtxKey = defaultTokenCtxKey
    }
}

// Set expiration time.
// If only set the expiration time,
// The refresh time will automatically be set to half of the expiration time.
func (j *jwt) setExpirationTime(expirationTime int64) {
    if expirationTime > 0 {
        j.expirationTime = time.Duration(expirationTime) * time.Second
    } else {
        j.expirationTime = defaultExpirationTime
    }
}

// Set refresh time.
// If only set the expiration time,
// The refresh time will automatically be set to half of the expiration time.
func (j *jwt) setRefreshTime(refreshTime int64) {
    if refreshTime > 0 {
        j.refreshTime = time.Duration(refreshTime) * time.Second
    } else {
        j.refreshTime = j.expirationTime / 2
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
    
    if j.publicKey, err = jwts.ParseRSAPublicKeyFromPEM(key); err != nil {
        return
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
    
    if j.privateKey, err = jwts.ParseRSAPrivateKeyFromPEM(key); err != nil {
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
