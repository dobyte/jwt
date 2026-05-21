package jwt

import (
	"time"

	"github.com/dobyte/jwt/internal/conv"
)

const (
	claimUUID      = "jti"
	claimIssuer    = "iss"
	claimIssueAt   = "iat"
	claimAudience  = "aud"
	claimExpired   = "exp"
	claimNotBefore = "nbf"
	claimSubject   = "sub"
)

type Payload map[string]any

// UUID Get the uuid of the payload.
func (p Payload) UUID() string {
	if v, ok := p[claimUUID]; ok {
		return conv.String(v)
	} else {
		return ""
	}
}

// Issuer Get the issuer of the payload.
func (p Payload) Issuer() string {
	if v, ok := p[claimIssuer]; ok {
		return conv.String(v)
	} else {
		return ""
	}
}

// IssueAt Get the issue at of the payload.
func (p Payload) IssueAt() time.Time {
	if v, ok := p[claimIssueAt]; ok {
		return time.Unix(int64(v.(float64)), 0)
	} else {
		return time.Time{}
	}
}

// Audience Get the audience of the payload.
func (p Payload) Audience() string {
	if v, ok := p[claimAudience]; ok {
		return conv.String(v)
	} else {
		return ""
	}
}

// Expired Get the expired of the payload.
func (p Payload) Expired() time.Time {
	if v, ok := p[claimExpired]; ok {
		return time.Unix(int64(v.(float64)), 0)
	} else {
		return time.Time{}
	}
}

// NotBefore Get the not before of the payload.
func (p Payload) NotBefore() time.Time {
	if v, ok := p[claimNotBefore]; ok {
		return time.Unix(int64(v.(float64)), 0)
	} else {
		return time.Time{}
	}
}

// Subject Get the subject of the payload.
func (p Payload) Subject() string {
	if v, ok := p[claimSubject]; ok {
		return conv.String(v)
	} else {
		return ""
	}
}
