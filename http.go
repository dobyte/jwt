package jwt

import (
	"context"
	"net/http"
	"strings"
	"time"
)

const (
	lookupTokenFromHeader = "header"
	lookupTokenFromQuery  = "query"
	lookupTokenFromCookie = "cookie"
	lookupTokenFromForm   = "form"
)

const (
	defaultPayloadCtxKey = "JWT_PAYLOAD"
	defaultTokenCtxKey   = "JWT_TOKEN"
)

type Http struct {
	jwt            *JWT
	tokenLocations [][2]string
}

func NewHttp(jwt *JWT) *Http {
	locations := strings.Split(jwt.opts.lookupLocations, ",")

	h := &Http{jwt: jwt, tokenLocations: make([][2]string, 0, len(locations))}

	for _, location := range locations {
		parts := strings.Split(strings.TrimSpace(location), ":")

		if len(parts) != 2 {
			continue
		}

		k := strings.TrimSpace(parts[0])
		v := strings.TrimSpace(parts[1])
		switch k {
		case lookupTokenFromHeader, lookupTokenFromQuery, lookupTokenFromCookie, lookupTokenFromForm:
			h.tokenLocations = append(h.tokenLocations, [2]string{k, v})
		}
	}

	if len(h.tokenLocations) == 0 {
		h.tokenLocations = append(h.tokenLocations, [2]string{lookupTokenFromHeader, "Authorization"})
	}

	return h
}

// RefreshToken Generates and returns a new token object from request.
// By default, the token expired error doesn't be ignored.
// You can ignore expired error by setting the `ignoreExpired` parameter.
func (h *Http) RefreshToken(r *http.Request, ignoreExpired ...bool) (*Token, error) {
	return h.jwt.RefreshToken(h.lookupToken(r), ignoreExpired...)
}

// DestroyToken Destroy a token.
// By default, the token expired error be ignored.
func (h *Http) DestroyToken(r *http.Request) error {
	token := h.lookupToken(r)
	if token == "" {
		return ErrMissingToken
	}

	return h.jwt.DestroyToken(token)
}

// ExtractToken Extracts and returns a token object from request.
// By default, the token expired error doesn't be ignored.
// You can ignore expired error by setting the `ignoreExpired` parameter.
func (h *Http) ExtractToken(r *http.Request, ignoreExpired ...bool) (*Token, error) {
	var token string

	if v := r.Context().Value(defaultTokenCtxKey); v != nil {
		token = v.(string)
	} else if token = h.lookupToken(r); token == "" {
		return nil, ErrMissingToken
	}

	claims, err := h.jwt.parseToken(token, ignoreExpired...)
	if err != nil {
		return nil, err
	}

	expiredAt := time.Unix(int64(claims[jwtExpired].(float64)), 0)
	refreshAt := time.Unix(int64(claims[jwtIssueAt].(float64)), 0).Add(h.jwt.opts.refreshDuration)

	return &Token{
		Token:     token,
		ExpiredAt: expiredAt,
		RefreshAt: refreshAt,
	}, nil
}

// ExtractPayload Retrieve payload from request.
// By default, the token expired error doesn't be ignored.
// You can ignore expired error by setting the `ignoreExpired` parameter.
func (h *Http) ExtractPayload(r *http.Request, ignoreExpired ...bool) (payload Payload, err error) {
	if v := r.Context().Value(defaultPayloadCtxKey); v != nil {
		payload = v.(Payload)
	} else {
		payload, _, err = h.parseRequest(r, ignoreExpired...)
	}
	return
}

// ExtractIdentity Retrieve identity from request.
// By default, the token expired error doesn't be ignored.
// You can ignore expired error by setting the `ignoreExpired` parameter.
func (h *Http) ExtractIdentity(r *http.Request, ignoreExpired ...bool) (interface{}, error) {
	if h.jwt.opts.identityKey == "" {
		return nil, ErrMissingIdentity
	}

	payload, err := h.ExtractPayload(r, ignoreExpired...)
	if err != nil {
		return nil, err
	}

	identity, ok := payload[h.jwt.opts.identityKey]
	if !ok {
		return nil, ErrMissingIdentity
	}

	return identity, nil
}

// Middleware Implemented basic JWT permission authentication.
func (h *Http) Middleware(r *http.Request) (*http.Request, error) {
	payload, token, err := h.parseRequest(r)
	if err != nil {
		return nil, err
	}

	ctx := r.Context()
	ctx = context.WithValue(ctx, defaultPayloadCtxKey, payload)
	ctx = context.WithValue(ctx, defaultTokenCtxKey, token)

	return r.WithContext(ctx), nil
}

// Parses and returns the payload and token from requests.
func (h *Http) parseRequest(r *http.Request, ignoreExpired ...bool) (payload Payload, token string, err error) {
	if token = h.lookupToken(r); token == "" {
		err = ErrMissingToken
		return
	}

	payload, err = h.jwt.ExtractPayload(token, ignoreExpired...)
	return
}

// Seeks and returns token from request.
// 1.from header    Authorization: Bearer ${token}
// 2.from query     ${url}?${cacheKey}=${token}
// 3.from cookie    Cookie: ${cacheKey}=${token}
// 4.from form      ${cacheKey}=${token}
func (h *Http) lookupToken(r *http.Request) (token string) {
	for _, item := range h.tokenLocations {
		if len(token) > 0 {
			break
		}
		switch item[0] {
		case lookupTokenFromHeader:
			token = h.lookupTokenFromHeader(r, item[1])
		case lookupTokenFromQuery:
			token = h.lookupTokenFromQuery(r, item[1])
		case lookupTokenFromCookie:
			token = h.lookupTokenFromCookie(r, item[1])
		case lookupTokenFromForm:
			token = h.lookupTokenFromForm(r, item[1])
		}
	}

	return
}

// Lookups and returns JWT token from the headers of request.
func (h *Http) lookupTokenFromHeader(r *http.Request, key string) string {
	switch val := r.Header.Get(key); key {
	case "Authorization":
		parts := strings.SplitN(val, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			return ""
		}
		return parts[1]
	default:
		return val
	}
}

// Lookups and returns JWT token from the query params of request.
func (h *Http) lookupTokenFromQuery(r *http.Request, key string) string {
	return r.URL.Query().Get(key)
}

// Lookups and returns JWT token from the cookies of request.
func (h *Http) lookupTokenFromCookie(r *http.Request, key string) string {
	cookie, _ := r.Cookie(key)
	return cookie.String()
}

// Lookups and returns JWT token from the post forms of request.
func (h *Http) lookupTokenFromForm(r *http.Request, key string) string {
	return r.Form.Get(key)
}
