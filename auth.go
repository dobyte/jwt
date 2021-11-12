package jwt

type (
	Auth interface {
		GenerateToken(identity string, payload ...Payload) (*Token, error)
	}

	auth struct {
		jwt
		cache       Cache
		identityKey string
	}

	AuthOptions struct {
		Options
	}
)

const defaultIdentityKey = "identity"

func NewAuth(opt *AuthOptions) (Auth, error) {
	a := new(auth)

	if err := a.init(&opt.Options); err != nil {
		return nil, err
	}

	return a, nil
}

func (a *auth) GenerateToken(identity string, payload ...Payload) (*Token, error) {
	var data Payload

	if len(payload) == 0 {
		data = make(Payload, 1)
	} else {
		data = payload[0]
	}

	data[a.identityKey] = identity

	token, id, err := a.generateToken(data)
	if err != nil {
		return nil, err
	}

	if a.cache != nil {
		if err = a.cache.Set(a.key(identity), id); err != nil {
			return nil, err
		}
	}

	return token, nil
}

func (a *auth) DestroyToken(token string) (err error) {
	if a.cache == nil {
		return
	}

	claims, err := a.parseToken(token, true)
	if err != nil {
		return
	}

	identity, ok := claims[a.identityKey]
	if !ok {
		return errIdentityMissing
	}

	key := a.key(identity.(string))

	oldId, err := a.cache.Get(key)
	if err != nil {
		return
	}

	if oldId == "" {
		return
	}

	if oldId != claims[jwtId].(string) {
		return errAuthElsewhere
	}

	return a.cache.Delete(key)
}

//
func (a *auth) GetIdentity(token string, ignoreExpired ...bool) (string, error) {
	claims, err := a.parseToken(token, ignoreExpired...)
	if err != nil {
		return "", err
	}

	identity, ok := claims[defaultIdentityKey]
	if !ok {
		return "", errIdentityMissing
	}

	return identity.(string), nil
}

func (a *auth) key(identity string) string {
	return ""
}
