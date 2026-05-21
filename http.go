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
// You can ignore expired error by setting the `isOmitExpired` parameter.
func (h *Http) RefreshToken(r *http.Request, isOmitExpired ...bool) (*Token, error) {
	return h.jwt.RefreshToken(h.doLookupToken(r), isOmitExpired...)
}

// DestroyToken Destroy a token.
// By default, the token expired error be ignored.
func (h *Http) DestroyToken(r *http.Request, isOmitExpired ...bool) error {
	if token := h.doLookupToken(r); token == "" {
		return ErrMissingToken
	} else {
		return h.jwt.DestroyToken(token, isOmitExpired...)
	}
}

// ExtractPayload Retrieve payload from request.
// By default, the token expired error doesn't be ignored.
// You can ignore expired error by setting the `isOmitExpired` parameter.
func (h *Http) ParseToken(r *http.Request, isOmitExpired ...bool) (payload Payload, err error) {
	if v := r.Context().Value(defaultPayloadCtxKey); v != nil {
		payload = v.(Payload)
	} else {
		_, payload, err = h.doParseRequest(r, isOmitExpired...)
	}

	return
}

// ExtractToken Extracts and returns a token object from request.
// By default, the token expired error doesn't be ignored.
// You can ignore expired error by setting the `ignoreExpired` parameter.
func (h *Http) ExtractToken(r *http.Request, isOmitExpired ...bool) (*Token, error) {
	var token string

	if v := r.Context().Value(defaultTokenCtxKey); v != nil {
		token = v.(string)
	} else if token = h.doLookupToken(r); token == "" {
		return nil, ErrMissingToken
	}

	claims, err := h.jwt.doParseToken(token, isOmitExpired...)
	if err != nil {
		return nil, err
	}

	expiredAt := time.Unix(int64(claims[claimExpired].(float64)), 0)
	refreshAt := time.Unix(int64(claims[claimIssueAt].(float64)), 0).Add(h.jwt.opts.refreshDuration)

	return &Token{
		Token:     token,
		ExpiredAt: expiredAt,
		RefreshAt: refreshAt,
	}, nil
}

// Middleware Implemented basic JWT permission authentication.
func (h *Http) Middleware(r *http.Request) (*http.Request, error) {
	token, payload, err := h.doParseRequest(r)
	if err != nil {
		return nil, err
	}

	ctx := r.Context()
	ctx = context.WithValue(ctx, defaultTokenCtxKey, token)
	ctx = context.WithValue(ctx, defaultPayloadCtxKey, payload)

	return r.WithContext(ctx), nil
}

// Parses and returns the payload and token from requests.
func (h *Http) doParseRequest(r *http.Request, isOmitExpired ...bool) (string, Payload, error) {
	token := h.doLookupToken(r)

	if token == "" {
		return "", nil, ErrMissingToken
	}

	payload, err := h.jwt.ParseToken(token, isOmitExpired...)
	if err != nil {
		return "", nil, err
	}

	return token, payload, nil
}

// Seeks and returns token from request.
// 1.from header    Authorization: Bearer ${token}
// 2.from query     ${url}?${cacheKey}=${token}
// 3.from cookie    Cookie: ${cacheKey}=${token}
// 4.from form      ${cacheKey}=${token}
func (h *Http) doLookupToken(r *http.Request) (token string) {
	for _, item := range h.tokenLocations {
		if len(token) > 0 {
			break
		}
		switch item[0] {
		case lookupTokenFromHeader:
			token = h.doLookupTokenFromHeader(r, item[1])
		case lookupTokenFromQuery:
			token = h.doLookupTokenFromQuery(r, item[1])
		case lookupTokenFromCookie:
			token = h.doLookupTokenFromCookie(r, item[1])
		case lookupTokenFromForm:
			token = h.doLookupTokenFromForm(r, item[1])
		}
	}

	return
}

// Lookups and returns JWT token from the headers of request.
func (h *Http) doLookupTokenFromHeader(r *http.Request, key string) string {
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
func (h *Http) doLookupTokenFromQuery(r *http.Request, key string) string {
	return r.URL.Query().Get(key)
}

// Lookups and returns JWT token from the cookies of request.
func (h *Http) doLookupTokenFromCookie(r *http.Request, key string) string {
	cookie, _ := r.Cookie(key)
	return cookie.String()
}

// Lookups and returns JWT token from the post forms of request.
func (h *Http) doLookupTokenFromForm(r *http.Request, key string) string {
	return r.Form.Get(key)
}
