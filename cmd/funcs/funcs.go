package funcs

import (
	"acme/types"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	b64 "encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
)

func Es256Sign(toSign string, key *ecdsa.PrivateKey) (string, error) {
	sha256 := crypto.SHA256.New()
	sha256.Write([]byte(toSign))
	hashToSign := sha256.Sum(nil) //write toSign to hash state machine and then dump
	R, S, err := ecdsa.Sign(rand.Reader, key, hashToSign)
	signature := b64.RawURLEncoding.EncodeToString(append(R.Bytes(), S.Bytes()...))
	return signature, err
}

func GetDir(client *http.Client, url string) (error, types.Dir) {
	var dir_resp types.Dir
	resp, err := client.Get(url) //to be renamed to https://pebble:14000/dir
	if err != nil {
		return err, dir_resp
	}
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err, dir_resp
	}
	err = json.Unmarshal(bodyBytes, &dir_resp)
	return err, dir_resp
}

func GetNonce(client *http.Client, url string) (string, error) {
	resp, err := client.Head(url)
	if err != nil {
		return "", err
	} else {
		if resp.StatusCode != 204 && resp.StatusCode != 200 {
			return "", errors.New("Bad Status " + strconv.Itoa(resp.StatusCode))
		}
		return resp.Header.Get("Replay-Nonce"), nil
	}
}

//POST a new account, returns the kid (Account Url) and orders Url
func PostAccountRequest(client *http.Client, nonce, url string, key *ecdsa.PrivateKey) (string, string, error) {
	//need RawURLEncoding that is b64url with no padding as RFC
	x := b64.RawURLEncoding.EncodeToString(key.PublicKey.X.Bytes())
	y := b64.RawURLEncoding.EncodeToString(key.PublicKey.Y.Bytes())
	jwk := types.Jwk{Crv: "P-256", Kty: "EC", X: x, Y: y} // Use: "sig", Kid: "1"}

	//Alg is ECDSA SHA256 on P256
	joseHead := types.JoseHeaderJwk{Alg: "ES256", Nonce: nonce, Url: url, Jwk: jwk}
	contact := []string{"mailto:admin@example.com"}
	payload := types.AccountObject{TermsOfServiceAgreed: true, Contact: contact, OnlyReturnExisting: false}

	jsonJoseHead, err := json.Marshal(joseHead)
	//println(string(jsonJoseHead))
	if err != nil {
		return "", "", errors.New("Failed Jsonify of Jose Header")
	}

	jsonPayload, err := json.Marshal(payload)
	//println(string(jsonPayload))
	if err != nil {
		return "", "", errors.New("Failed Jsonify of Account payload")
	}
	//From spec: ECDSA using P-256 and SHA-256
	toSign := b64.RawURLEncoding.EncodeToString(jsonJoseHead) +
		"." +
		b64.RawURLEncoding.EncodeToString(jsonPayload)

	signature, err := Es256Sign(toSign, key)
	if err != nil {
		return "", "", errors.New("Signature Failed")
	}

	//Form Request body
	body := types.JWSBody{
		Payload:   b64.RawURLEncoding.EncodeToString(jsonPayload),
		Protected: b64.RawURLEncoding.EncodeToString(jsonJoseHead),
		Signature: signature,
	}
	jsonBody, err := json.Marshal(body)
	//fmt.Println(string(jsonBody))
	if err != nil {
		return "", "", errors.New("Failed Jsonify of Account Body")
	}
	resp, err := client.Post(
		url,
		"application/jose+json",
		bytes.NewBuffer(jsonBody),
	)
	if err != nil {
		return "", "", errors.New("Failed Post request for New Account")
	}
	if resp.StatusCode == 201 {
		body, _ := ioutil.ReadAll(resp.Body)
		//bodyString := string(body)
		//log.Println(bodyString)
		//quick way of parsing a json without caring of all the fields
		var result map[string]interface{}
		json.Unmarshal(body, &result)
		orders := result["orders"].(string)
		kid := resp.Header.Get("Location") //Account url
		return kid, orders, nil
	}
	return "", "", errors.New("Bad Status " + strconv.Itoa(resp.StatusCode))

}

//POST a request for a new certificate issuance. Returns the list of authorizations URLs (one x domain), the finalize Url, and the order url in location hdr
func PostNewOrder(client *http.Client, url string, nonce string, identifiers []types.Identifier, key *ecdsa.PrivateKey, kid string) ([]string, string, string, error) {
	joseHead := types.JoseHeaderKid{Alg: "ES256", Nonce: nonce, Url: url, Kid: kid}
	payload := types.OrderObject{Identifiers: identifiers}

	jsonJoseHead, err := json.Marshal(joseHead)
	//println(string(jsonJoseHead))
	if err != nil {
		return nil, "", "", errors.New("Failed Jsonify of Jose Header")
	}

	jsonPayload, err := json.Marshal(payload)
	//println(string(jsonJoseHead))
	if err != nil {
		return nil, "", "", errors.New("Failed Jsonify of Payload")
	}

	toSign := b64.RawURLEncoding.EncodeToString(jsonJoseHead) +
		"." +
		b64.RawURLEncoding.EncodeToString(jsonPayload)

	signature, err := Es256Sign(toSign, key)

	body := types.JWSBody{
		Payload:   b64.RawURLEncoding.EncodeToString(jsonPayload),
		Protected: b64.RawURLEncoding.EncodeToString(jsonJoseHead),
		Signature: signature,
	}

	jsonBody, err := json.Marshal(body)
	//fmt.Println(string(jsonBody))
	if err != nil {
		return nil, "", "", errors.New("Failed Jsonify of New Order Body")
	}
	resp, err := client.Post(
		url,
		"application/jose+json",
		bytes.NewBuffer(jsonBody),
	)
	if err != nil {
		return nil, "", "", errors.New("Failed Post request for New Order")
	} else if resp.StatusCode == 201 {
		body, _ := ioutil.ReadAll(resp.Body)
		bodyString := string(body)
		log.Println(bodyString)
		//quick way of parsing a json without caring of all the fields
		var result map[string]interface{}
		json.Unmarshal(body, &result)

		//parse the array in json field
		var authorizations []string //urls
		auth := result["authorizations"].([]interface{})
		for _, v := range auth {
			authorizations = append(authorizations, v.(string))
		}

		finalize := result["finalize"].(string)
		order := resp.Header.Get("location")
		return authorizations, finalize, order, nil
	}
	return nil, "", "", errors.New("Bad Status " + strconv.Itoa(resp.StatusCode))
}

//Post-as-GET to authorization url to get a Challenge
func PostAsGetAuthorization(client *http.Client, url string, nonce string, key *ecdsa.PrivateKey, kid string) ([]types.Challenge, error) {
	joseHead := types.JoseHeaderKid{Alg: "ES256", Nonce: nonce, Url: url, Kid: kid}
	payload := ""

	jsonJoseHead, err := json.Marshal(joseHead)
	//println(string(jsonJoseHead))
	if err != nil {
		return nil, errors.New("Failed Jsonify of Jose Header")
	}

	toSign := b64.RawURLEncoding.EncodeToString(jsonJoseHead) +
		"." +
		payload

	signature, err := Es256Sign(toSign, key)

	body := types.JWSBody{
		Payload:   payload,
		Protected: b64.RawURLEncoding.EncodeToString(jsonJoseHead),
		Signature: signature,
	}

	jsonBody, err := json.Marshal(body)
	//fmt.Println(string(jsonBody))
	if err != nil {
		return nil, errors.New("Failed Jsonify of PostAsGet Challenge Body")
	}
	resp, err := client.Post(
		url,
		"application/jose+json",
		bytes.NewBuffer(jsonBody),
	)
	if err != nil {
		return nil, errors.New("Failed PostAsGet request for Challenges")
	} else if resp.StatusCode == 200 {
		body, _ := ioutil.ReadAll(resp.Body)
		bodyString := string(body)
		log.Println(bodyString)

		var resultSingle map[string]interface{}
		json.Unmarshal(body, &resultSingle)
		identifier := resultSingle["identifier"].(map[string]interface{})
		domain := identifier["value"].(string)

		//parse the array in json field
		var result map[string][]interface{}
		json.Unmarshal(body, &result)
		var challenges []types.Challenge

		//challs is an array of interface, who in turns are Json objects, hence again map[string]interface{}

		challs := result["challenges"]
		for _, c := range challs {
			var chall types.Challenge
			chall.Type = c.(map[string]interface{})["type"].(string)
			chall.Status = c.(map[string]interface{})["status"].(string)
			chall.Token = c.(map[string]interface{})["token"].(string)
			chall.Url = c.(map[string]interface{})["url"].(string)
			chall.Domain = domain
			chall.Auth = url
			if chall.Type != "tls-alpn-01" {
				challenges = append(challenges, chall)
			}
		}
		return challenges, nil
	}
	return nil, errors.New("Bad Status " + strconv.Itoa(resp.StatusCode))
}

//Send a POST req to chall url to trigger verification
func PostChallenge(client *http.Client, url string, nonce string, key *ecdsa.PrivateKey, kid string) error {
	joseHead := types.JoseHeaderKid{Alg: "ES256", Nonce: nonce, Url: url, Kid: kid}
	payload := types.EmptyBody{}

	jsonJoseHead, err := json.Marshal(joseHead)
	//println(string(jsonJoseHead))
	if err != nil {
		return errors.New("Failed Jsonify of Jose Header")
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return errors.New("Failed Jsonify of Payload")
	}
	toSign := b64.RawURLEncoding.EncodeToString(jsonJoseHead) +
		"." +
		b64.RawURLEncoding.EncodeToString(jsonPayload)

	signature, err := Es256Sign(toSign, key)

	body := types.JWSBody{
		Payload:   b64.RawURLEncoding.EncodeToString(jsonPayload),
		Protected: b64.RawURLEncoding.EncodeToString(jsonJoseHead),
		Signature: signature,
	}

	jsonBody, err := json.Marshal(body)
	//fmt.Println(string(jsonBody))
	if err != nil {
		return errors.New("Failed Jsonify of Challenge Body")
	}
	resp, err := client.Post(
		url,
		"application/jose+json",
		bytes.NewBuffer(jsonBody),
	)
	if err != nil {
		return errors.New("Failed Post request for Challenges")
	} else if resp.StatusCode == 200 {
		//body, _ := ioutil.ReadAll(resp.Body)
		//bodyString := string(body)
		//log.Println(bodyString)
		return nil
	}
	return errors.New("Bad Status " + strconv.Itoa(resp.StatusCode))
}

//POST-as-GET to auth url to check on status
func CheckChallengeStatus(client *http.Client, url string, nonce string, key *ecdsa.PrivateKey, kid string) (string, error) {
	joseHead := types.JoseHeaderKid{Alg: "ES256", Nonce: nonce, Url: url, Kid: kid}
	payload := ""

	jsonJoseHead, err := json.Marshal(joseHead)
	//println(string(jsonJoseHead))
	if err != nil {
		return "", errors.New("Failed Jsonify of Jose Header")
	}

	toSign := b64.RawURLEncoding.EncodeToString(jsonJoseHead) +
		"." +
		payload

	signature, err := Es256Sign(toSign, key)

	body := types.JWSBody{
		Payload:   payload,
		Protected: b64.RawURLEncoding.EncodeToString(jsonJoseHead),
		Signature: signature,
	}

	jsonBody, err := json.Marshal(body)
	//fmt.Println(string(jsonBody))
	if err != nil {
		return "", errors.New("Failed Jsonify of PostAsGet Challenge Body")
	}
	resp, err := client.Post(
		url,
		"application/jose+json",
		bytes.NewBuffer(jsonBody),
	)
	if err != nil {
		return "", errors.New("Failed PostAsGet request for Challenges")
	} else if resp.StatusCode == 200 {
		body, _ := ioutil.ReadAll(resp.Body)
		bodyString := string(body)
		log.Println(bodyString)

		var result map[string]interface{}
		json.Unmarshal(body, &result)
		status := result["status"].(string)
		return status, nil
	}
	return "", errors.New("Bad Status " + strconv.Itoa(resp.StatusCode))
}

//check order status and return certificate download url if valid
func PostAsGetOrder(client *http.Client, url string, nonce string, key *ecdsa.PrivateKey, kid string) (string, string, error) {
	joseHead := types.JoseHeaderKid{Alg: "ES256", Nonce: nonce, Url: url, Kid: kid}
	payload := ""

	jsonJoseHead, err := json.Marshal(joseHead)
	//println(string(jsonJoseHead))
	if err != nil {
		return "", "", errors.New("Failed Jsonify of Jose Header")
	}

	toSign := b64.RawURLEncoding.EncodeToString(jsonJoseHead) +
		"." +
		payload

	signature, err := Es256Sign(toSign, key)

	body := types.JWSBody{
		Payload:   payload,
		Protected: b64.RawURLEncoding.EncodeToString(jsonJoseHead),
		Signature: signature,
	}

	jsonBody, err := json.Marshal(body)
	//fmt.Println(string(jsonBody))
	if err != nil {
		return "", "", errors.New("Failed Jsonify of PostAsGet Order Body")
	}
	resp, err := client.Post(
		url,
		"application/jose+json",
		bytes.NewBuffer(jsonBody),
	)
	if err != nil {
		return "", "", errors.New("Failed PostAsGet request for Order")
	} else if resp.StatusCode == 201 || resp.StatusCode == 200 {
		body, _ := ioutil.ReadAll(resp.Body)
		bodyString := string(body)
		log.Println(bodyString)
		var result map[string]interface{}
		json.Unmarshal(body, &result)

		//parse the array in json field
		certificate := ""
		status := result["status"].(string)
		if status == "valid" {
			certificate = result["certificate"].(string)
		}
		return status, certificate, nil
	}
	return "invalid", "", errors.New("Bad Status " + strconv.Itoa(resp.StatusCode))
}

//POST request to finalize with csr
func PostFinalize(client *http.Client, url string, nonce string, key *ecdsa.PrivateKey, kid string, csr []byte) error {
	joseHead := types.JoseHeaderKid{Alg: "ES256", Nonce: nonce, Url: url, Kid: kid}
	payload := types.CertRequest{Csr: b64.RawURLEncoding.EncodeToString(csr)}

	jsonJoseHead, err := json.Marshal(joseHead)
	if err != nil {
		return errors.New("Failed Jsonify of Jose Header")
	}
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return errors.New("Failed Jsonify of Payload")
	}
	toSign := b64.RawURLEncoding.EncodeToString(jsonJoseHead) +
		"." +
		b64.RawURLEncoding.EncodeToString(jsonPayload)

	signature, err := Es256Sign(toSign, key)
	if err != nil {
		log.Println("error signing")
		return err
	}

	body := types.JWSBody{
		Payload:   b64.RawURLEncoding.EncodeToString(jsonPayload),
		Protected: b64.RawURLEncoding.EncodeToString(jsonJoseHead),
		Signature: signature,
	}

	jsonBody, err := json.Marshal(body)
	//fmt.Println(string(jsonBody))
	if err != nil {
		return errors.New("Failed Jsonify of finalize Body")
	}
	resp, err := client.Post(
		url,
		"application/jose+json",
		bytes.NewBuffer(jsonBody),
	)
	if err != nil {
		return errors.New("Failed Post request for finalize")
	} else if resp.StatusCode == 200 || resp.StatusCode == 201 {
		body, _ := ioutil.ReadAll(resp.Body)
		bodyString := string(body)
		log.Println(bodyString)
		var result map[string]interface{}
		json.Unmarshal(body, &result)
		return nil
	} else {
		body, _ := ioutil.ReadAll(resp.Body)
		bodyString := string(body)
		log.Println(bodyString)
		return errors.New("Bad Status " + strconv.Itoa(resp.StatusCode))
	}
}

//parsing inspired by https://gist.github.com/laher/5795578
func decodePem(certInput string) tls.Certificate {
	var cert tls.Certificate
	certPEMBlock := []byte(certInput)
	var certDERBlock *pem.Block
	for {
		certDERBlock, certPEMBlock = pem.Decode(certPEMBlock)
		if certDERBlock == nil {
			break
		}
		if certDERBlock.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, certDERBlock.Bytes)
		}
	}
	return cert
}

func PostAsGetCertificate(client *http.Client, url string, nonce string, key *ecdsa.PrivateKey, kid string) (tls.Certificate, []byte, error) {
	joseHead := types.JoseHeaderKid{Alg: "ES256", Nonce: nonce, Url: url, Kid: kid}
	payload := ""

	jsonJoseHead, err := json.Marshal(joseHead)
	//println(string(jsonJoseHead))
	if err != nil {
		return tls.Certificate{}, nil, errors.New("Failed Jsonify of Jose Header")
	}

	toSign := b64.RawURLEncoding.EncodeToString(jsonJoseHead) +
		"." +
		payload

	signature, err := Es256Sign(toSign, key)

	body := types.JWSBody{
		Payload:   payload,
		Protected: b64.RawURLEncoding.EncodeToString(jsonJoseHead),
		Signature: signature,
	}

	jsonBody, err := json.Marshal(body)
	//fmt.Println(string(jsonBody))
	if err != nil {
		return tls.Certificate{}, nil, errors.New("Failed Jsonify of PostAsGet Certificate Body")
	}
	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonBody))

	req.Header = http.Header{
		"Content-Type": []string{"application/jose+json"},
		"Accept":       []string{"application/pkix-cert"},
	}
	resp, err := client.Do(req)

	if err != nil {
		return tls.Certificate{}, nil, errors.New("Failed PostAsGet request for Certificate")
	} else if resp.StatusCode == 201 || resp.StatusCode == 200 {

		body, _ := ioutil.ReadAll(resp.Body)
		bodyString := string(body)
		certChain := decodePem(bodyString)
		return certChain, body, nil
	}
	return tls.Certificate{}, nil, errors.New("Bad Status " + strconv.Itoa(resp.StatusCode))
}

func PostRevocation(client *http.Client, url string, nonce string, kid string, key *ecdsa.PrivateKey, cert []byte) error {
	joseHead := types.JoseHeaderKid{Alg: "ES256", Nonce: nonce, Url: url, Kid: kid}
	payload := types.CertRevocation{Certificate: b64.RawURLEncoding.EncodeToString(cert)}

	jsonJoseHead, err := json.Marshal(joseHead)
	if err != nil {
		return errors.New("Failed Jsonify of Jose Header")
	}
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return errors.New("Failed Jsonify of Payload")
	}
	toSign := b64.RawURLEncoding.EncodeToString(jsonJoseHead) +
		"." +
		b64.RawURLEncoding.EncodeToString(jsonPayload)

	signature, err := Es256Sign(toSign, key)
	if err != nil {
		log.Println("error signing")
		return err
	}

	body := types.JWSBody{
		Payload:   b64.RawURLEncoding.EncodeToString(jsonPayload),
		Protected: b64.RawURLEncoding.EncodeToString(jsonJoseHead),
		Signature: signature,
	}

	jsonBody, err := json.Marshal(body)
	//fmt.Println(string(jsonBody))
	if err != nil {
		return errors.New("Failed Jsonify of revocation Body")
	}
	resp, err := client.Post(
		url,
		"application/jose+json",
		bytes.NewBuffer(jsonBody),
	)
	if err != nil {
		body, _ := ioutil.ReadAll(resp.Body)
		bodyString := string(body)
		log.Println(bodyString)
		return err
	} else if resp.StatusCode == 200 || resp.StatusCode == 201 {
		fmt.Println("revocation ok")
		return nil
	} else {
		body, _ := ioutil.ReadAll(resp.Body)
		bodyString := string(body)
		log.Println(bodyString)
	}
	return errors.New("Bad Status " + strconv.Itoa(resp.StatusCode))
}
