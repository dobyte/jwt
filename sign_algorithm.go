package jwt

type SignAlgorithm string

func (s SignAlgorithm) String() string {
	return string(s)
}

const (
	HS256 SignAlgorithm = "HS256"
	HS512 SignAlgorithm = "HS512"
	HS384 SignAlgorithm = "HS384"

	RS256 SignAlgorithm = "RS256"
	RS384 SignAlgorithm = "RS384"
	RS512 SignAlgorithm = "RS512"

	ES256 SignAlgorithm = "ES256"
	ES384 SignAlgorithm = "ES384"
	ES512 SignAlgorithm = "ES512"
)
