package types

type Meta struct {
	ExternalAccountRequired bool   `json:"extrnalAccountRequired"`
	TermsOfService          string `json:"termsOfService"`
}

type Dir struct {
	//stores url for acme interactions
	KeyChange  string `json:"keyChange"`
	Meta       Meta   `json:"meta"`
	NewAccount string `json:"newAccount"`
	NewNonce   string `json:"newNonce"`
	NewOrder   string `json:"newOrder"`
	RevokeCert string `json:"RevokeCert"`
}
type Jwk struct {
	//Json Web Key
	Crv string `json:"crv"`
	Kty string `json:"kty"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Use string `json:"use,omitempty"`
	Kid string `json:"kid,omitempty"`
}
type JoseHeaderJwk struct {
	Alg   string `json:"alg"`   //alg used for signing (NOT MAC)
	Nonce string `json:"nonce"` //nonce get by getNonce()
	Url   string `json:"url"`   //url to
	Jwk   Jwk    `json:"jwk"`   //pub key
}

type JoseHeaderKid struct {
	Alg   string `json:"alg"`   //alg used for signing (NOT MAC)
	Nonce string `json:"nonce"` //nonce get by getNonce()
	Url   string `json:"url"`   //url to
	Kid   string `json:"kid"`   //url received by POSTing to new-account
}

type AccountObject struct {
	TermsOfServiceAgreed bool     `json:"termsOfServiceAgreed"`
	Contact              []string `json:"contact"`
	OnlyReturnExisting   bool     `json:"onlyReturnExisting"`
}

type JWSBody struct {
	// corresponds to Flattened JWS Json Serialization
	Payload   string `json:"payload"`
	Protected string `json:"protected"`
	Signature string `json:"signature"`
}
type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}
type OrderObject struct {
	//For a new order, include only the identifiers
	Status         string       `json:"status,omitempty"`
	Identifiers    []Identifier `json:"identifiers"`
	Type           string       `json:"type,omitempty"`
	Value          string       `json:"value,omitempty"`
	Authorizations []string     `json:"authorizations,omitempty"`
	Finalize       string       `json:"finalize,omitempty"`
}

type Challenge struct {
	Type   string `json:"type"`
	Url    string `json:"url"`
	Token  string `json:"token"`
	Status string `json:"status"`
	Domain string //additional field not in RFC to derive domain for chall, because pebble can shuffle the domain from authorizations
	Auth   string //additional field. Auth url to check status of the authorization (i.e challenge fullfiled)
}

type EmptyBody struct {
	Body string `json:"body,omitempty"`
}

type CertRequest struct {
	Csr string `json:"csr"`
}

type CertRevocation struct {
	Certificate string `json:"certificate"`
}
