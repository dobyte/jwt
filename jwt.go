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
    
    Payload map[string]interface{}
    
    Cache interface {
    }
    
    JWT interface {
        // Middleware Implemented basic JWT permission authentication.
        Middleware(r *http.Request) (*http.Request, error)
        // GenerateToken Generates and returns a new token object.
        GenerateToken(payload map[string]interface{}) (*Token, error)
        // RefreshToken generates and returns a new token object depend on old token.
        RefreshToken(token string) (*Token, error)
        // ParseToken Parses and returns a claims map from the token.
        // Ignore token expired error, If necessary, you need to judge the expiration by yourself.
        ParseToken(token string) (jwts.MapClaims, error)
        // SeekToken Seeks and returns token from request.
        // 1.from header    Authorization: Bearer ${token}
        // 2.from query     ${url}?${key}=${token}
        // 3.from cookie    Cookie: ${key}=${token}
        // 4.from form      ${key}=${token}
        SeekToken(r *http.Request) (token string)
        // GetCtxValue Get value from request's context.
        GetCtxValue(r *http.Request, key string) interface{}
    }
)

type Options struct {
    Issuer      string
    Algorithm   string
    SecretKey   string
    RefreshTime int64
    ExpiredTime int64
    TokenSeeks  string
    
    // public key file or public key.
    PublicKey string
    
    // private key file or private key.
    PrivateKey string
}

type jwt struct {
    issuer      string
    algorithm   string
    expiredMode int
    expiredTime time.Duration
    refreshTime time.Duration
    tokenCtxKey string
    tokenSeeks  [][2]string
    publicKey   *rsa.PublicKey
    privateKey  *rsa.PrivateKey
    secretKey   []byte
}

type Token struct {
    Token     string `json:"token"`
    ExpiredAt string `json:"expired_at"`
    RefreshAt string `json:"refresh_at"`
}

const (
    jwtAudience      = "aud"
    jwtId            = "jti"
    jwtIssueAt       = "iat"
    jwtExpiredAt     = "exp"
    jwtRefreshAt     = "ref"
    jwtIssuer        = "iss"
    jwtNotBefore     = "nbf"
    jwtSubject       = "sub"
    jwtExclusiveCode = "esc"
    noDetailReason   = "no detail reason"
)

const (
    tokenSeekFromHeader  = "header"
    tokenSeekFromQuery   = "query"
    tokenSeekFromCookie  = "cookie"
    tokenSeekFromForm    = "form"
    tokenSeekFieldHeader = "Authorization"
    authorizationBearer  = "Bearer"
    
    HS256 = "HS256"
    HS512 = "HS512"
    HS384 = "HS384"
    RS256 = "RS256"
    RS384 = "RS384"
    RS512 = "RS512"
    ES256 = "ES256"
    ES384 = "ES384"
    ES512 = "ES512"
    
    defaultAlgorithm      = HS256
    defaultExpirationTime = time.Hour
    defaultPayloadCtxKey  = "jwt_payload"
    defaultTokenCtxKey    = "jwt_token"
)

func NewJwt(opt *Options) (JWT, error) {
    j := new(jwt)
    j.setIssuer(opt.Issuer)
    j.setTokenSeeks(opt.TokenSeeks)
    j.setExpiredTime(opt.ExpiredTime)
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

// Middleware Implemented basic JWT permission authentication.
func (j *jwt) Middleware(r *http.Request) (*http.Request, error) {
    token := j.SeekToken(r)
    if token == "" {
        return nil, errMissingToken
    }
    
    claims, err := j.ParseToken(token)
    if err != nil {
        return nil, err
    }
    
    payload := make(Payload)
    for k, v := range claims {
        switch k {
        case jwtAudience, jwtExpiredAt, jwtRefreshAt, jwtId, jwtIssueAt, jwtIssuer, jwtNotBefore, jwtSubject:
            // ignore the standard claims
        default:
            payload[k] = v
        }
    }
    
    ctx := r.Context()
    
    ctx = context.WithValue(ctx, defaultPayloadCtxKey, payload)
    
    ctx = context.WithValue(ctx, defaultTokenCtxKey, token)
    
    return r.WithContext(ctx), nil
}

// GenerateToken Generates and returns a new token object.
func (j *jwt) GenerateToken(payload map[string]interface{}) (*Token, error) {
    var (
        claims    = make(jwts.MapClaims)
        now       = time.Now()
        expiredAt = now.Add(j.expiredTime)
        refreshAt = now.Add(j.refreshTime)
    )
    
    claims[jwtIssuer] = j.issuer
    claims[jwtIssueAt] = now.Unix()
    claims[jwtExpiredAt] = expiredAt.Unix()
    claims[jwtRefreshAt] = refreshAt.Unix()
    claims[jwtExclusiveCode] = now.UnixNano()
    for k, v := range payload {
        switch k {
        case jwtIssuer, jwtIssueAt, jwtExpiredAt, jwtRefreshAt, jwtExclusiveCode:
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
        ExpiredAt: expiredAt.Format(time.RFC3339),
        RefreshAt: refreshAt.Format(time.RFC3339),
    }, nil
}

// RefreshToken generates and returns a new token object depend on old token.
func (j *jwt) RefreshToken(token string) (*Token, error) {
    var (
        err       error
        claims    jwts.MapClaims
        newClaims jwts.MapClaims
    )
    
    claims, err = j.ParseToken(token)
    if err != nil {
        return nil, err
    }
    
    now := time.Now()
    
    if ref, ok := claims[jwtRefreshAt]; !ok {
        return nil, errInvalidToken
    } else if int64(ref.(float64)) < now.Unix() {
        return nil, errExpiredToken
    }
    
    newClaims = make(jwts.MapClaims)
    for k, v := range claims {
        newClaims[k] = v
    }
    
    var (
        expiredAt = now.Add(j.expiredTime)
        refreshAt = now.Add(j.refreshTime)
    )
    
    newClaims[jwtExpiredAt] = expiredAt.Unix()
    newClaims[jwtRefreshAt] = refreshAt.Unix()
    
    token, err = j.signToken(newClaims)
    if err != nil {
        return nil, err
    }
    
    return &Token{
        Token:     token,
        ExpiredAt: expiredAt.Format(time.RFC3339),
        RefreshAt: refreshAt.Format(time.RFC3339),
    }, nil
}

// ParseToken Parses and returns a claims map from the token.
// Ignore token expired error, If necessary, you need to judge the expiration by yourself.
func (j *jwt) ParseToken(token string) (jwts.MapClaims, error) {
    jt, err := j.parseToken(token)
    if err != nil {
        switch e := err.(type) {
        case *jwts.ValidationError:
            switch e.Errors {
            case jwts.ValidationErrorExpired:
                // ignore token expired error
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
    
    return jt.Claims.(jwts.MapClaims), nil
}

func (j *jwt) GetPayload(r *http.Request) interface{} {
    return r.Context().Value(defaultPayloadCtxKey)
}

// GetCtxValue Get value from request's context.
func (j *jwt) GetCtxValue(r *http.Request, key string) interface{} {
    return r.Context().Value(key)
}

// SeekToken Seeks and returns token from request.
// 1.from header    Authorization: Bearer ${token}
// 2.from query     ${url}?${key}=${token}
// 3.from cookie    Cookie: ${key}=${token}
// 4.from form      ${key}=${token}
func (j *jwt) SeekToken(r *http.Request) (token string) {
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

// Parse the token
func (j *jwt) parseToken(token string) (*jwts.Token, error) {
    return jwts.Parse(token, func(t *jwts.Token) (interface{}, error) {
        if jwts.GetSigningMethod(j.algorithm) != t.Method {
            return nil, errSigningMethodNotMatch
        }
        
        if j.isHMAC() {
            return j.secretKey, nil
        } else {
            return j.publicKey, nil
        }
    })
}

// Signings and returns a token depend on the claims.
func (j *jwt) signToken(claims jwts.MapClaims) (token string, err error) {
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

// Check whether the signature method is HMAC.
func (j *jwt) isHMAC() bool {
    switch j.algorithm {
    case HS256, HS384, HS512:
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
        return errInvalidSigningMethod
    }
    
    return nil
}

// SetTokenLookup Set the token search location.
func (j *jwt) setTokenSeeks(tokenLookup string) {
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
func (j *jwt) setExpiredTime(expirationTime int64) {
    if expirationTime > 0 {
        j.expiredTime = time.Duration(expirationTime) * time.Second
    } else {
        j.expiredTime = defaultExpirationTime
    }
}

// Set refresh time.
// If only set the expiration time,
// The refresh time will automatically be set to half of the expiration time.
func (j *jwt) setRefreshTime(refreshTime int64) {
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
