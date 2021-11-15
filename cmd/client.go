package main

import (
	"acme/dns"
	"acme/funcs"
	"acme/httpChall"
	"acme/terminator"
	"acme/tlsServer"
	"acme/types"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/jessevdk/go-flags"
	mdns "github.com/miekg/dns"
)

//GLOBALS
var CURVE elliptic.Curve = elliptic.P256()

type cli struct {
	Dir     string   `long:"dir" description:"DIR_URL"`
	Record  string   `long:"record" description:"IPV4_ADDRESS"`
	Domains []string `long:"domain" description:"DOMAIN"`
	Revoke  bool     `long:"revoke" description:"revoke cert"`
}

//_____________________________________________________________________________________________________________________________________FUNCS

//Return the DER encoding of the csr
func makeCSR(domains []string, key *ecdsa.PrivateKey) ([]byte, error) {
	commonName := domains[0]
	san := []string{commonName}

	for _, name := range domains {
		if name != commonName {
			san = append(san, name)
		}
	}

	template := x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: commonName},
		DNSNames: san,
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
	if err != nil {
		return nil, err
	}
	return csr, nil
}

//Derives a key_auth string from token and public key
func deriveKeyAuthFromTokens(challs []types.Challenge, key *ecdsa.PrivateKey) []string {
	//need RawURLEncoding that is b64url with no padding as RFC
	x := b64.RawURLEncoding.EncodeToString(key.PublicKey.X.Bytes())
	y := b64.RawURLEncoding.EncodeToString(key.PublicKey.Y.Bytes())
	jwk := types.Jwk{Crv: "P-256", Kty: "EC", X: x, Y: y}
	jwkJson, _ := json.Marshal(jwk)
	sha256 := crypto.SHA256.New()
	sha256.Write(jwkJson)
	thumbprint := b64.RawURLEncoding.EncodeToString(sha256.Sum(nil))
	var key_auths []string
	for _, chall := range challs {
		key_auths = append(key_auths, chall.Token+"."+thumbprint)
	}
	return key_auths
}

//define and parse cli
func parseFlags() (cli, string) {
	var opts cli
	args, _ := flags.Parse(&opts)
	if opts.Dir == "" {
		log.Fatal("specify directory of pebble")
	}
	if opts.Record == "" {
		log.Fatal("specify A record for DNS")
	}
	if len(opts.Domains) == 0 {
		log.Fatal("specify domain for cert")
	}
	if len(args) != 1 {
		log.Fatal("specify only one challenge")
	}
	choice := args[0]
	if choice != "dns01" && choice != "http01" {
		log.Fatal("challenge not supported")
	}
	return opts, choice
}

func loadCert() http.Client {
	caCert, err := ioutil.ReadFile("../project/pebble.minica.pem")
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	//define client
	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caCertPool,
			},
		},
	}
	return client
}

func checkDnsUp(domain string) bool {
	fmt.Println("Checking if Dns is up...")
	for {
		time.Sleep(time.Second * 1)
		c := new(mdns.Client)
		message := new(mdns.Msg)
		message.SetQuestion(domain+".", mdns.TypeA)
		in, _, err := c.Exchange(message, "127.0.0.1:10053")
		if err != nil {
			continue
		}
		if in != nil {
			return true
		}
	}
}

func checkHttpUp() bool {
	fmt.Println("Checking if Http is up...")
	for {
		time.Sleep(time.Second * 1)
		resp, err := http.Get("http://127.0.0.1:5002/test")
		if err != nil {
			continue
		}
		if resp.StatusCode == http.StatusOK {
			return true
		}
	}
}

//____________________________________________________________________________________________________________________________________CLIENT
func main() {
	var opts cli
	opts, choice := parseFlags()
	//load pebble cert

	key, err := ecdsa.GenerateKey(CURVE, rand.Reader)
	if err != nil {
		log.Fatal("Problem generating key pairs")
	}

	client := loadCert()
	//get pebble urls
	dirResp := types.Dir{}
	for {
		err, dirResp = funcs.GetDir(&client, opts.Dir)
		if err != nil {
			log.Fatal("Problem getting dir")
		} else {
			break
		}
	}
	nonce := ""
	kid := ""
	//create account
	for {
		nonce, err = funcs.GetNonce(&client, dirResp.NewNonce)
		kid, _, err = funcs.PostAccountRequest(&client, nonce, dirResp.NewAccount, key)
		if err != nil {
			log.Println("Problem posting account")
		} else {
			break
		}
	}
	identifiers := []types.Identifier{}
	for _, d := range opts.Domains {
		id := types.Identifier{Type: "dns", Value: d}
		identifiers = append(identifiers, id)
	}
	authorizations := make([]string, 0)
	finalize := ""
	order := ""
	//create new order
	for {
		nonce, err = funcs.GetNonce(&client, dirResp.NewNonce)
		authorizations, finalize, order, err = funcs.PostNewOrder(&client, dirResp.NewOrder, nonce, identifiers, key, kid)
		if err != nil {
			log.Println("problem getting auth")
		} else {
			break
		}
	}

	//for each domain we get an authorization url from which we can download the challenge(token)
	var challenges []types.Challenge //url to bootstrap challs, token, type, status
	for _, auth := range authorizations {
		for {
			nonce, err = funcs.GetNonce(&client, dirResp.NewNonce)
			if err != nil {
				log.Println(err.Error())
				continue
			}
			challs, err := funcs.PostAsGetAuthorization(&client, auth, nonce, key, kid)
			if err != nil {
				log.Println(err.Error())
				continue
			} else {
				challenges = append(challenges, challs...)
				break
			}
		}
	}

	var filteredChallenges []types.Challenge
	var tokens []string

	challType := ""
	if choice == "dns01" {
		challType = "dns-01"
	} else if choice == "http01" {
		challType = "http-01"
	}
	//this array is used for domain names relativelly to dns
	domains := make([]string, 0)
	for i := 0; i < len(challenges); i++ {
		if challenges[i].Type == challType {
			filteredChallenges = append(filteredChallenges, challenges[i])
			tokens = append(tokens, challenges[i].Token)
			domains = append(domains, challenges[i].Domain)
		}
	}
	key_auths := deriveKeyAuthFromTokens(filteredChallenges, key)

	stopHttp := make(chan bool)
	stopDns := make(chan bool)
	dnsServeChall := false
	fmt.Println("Bootstrapping challs...")
	//sepate dns logic for http and dns challs
	if choice == "dns01" {
		dnsServeChall = true
		for i, chall := range filteredChallenges {
			go dns.Start([]string{domains[i]}, []string{key_auths[i]}, stopDns, dnsServeChall, opts.Record)
			//time.Sleep(3 * time.Second)
			_ = checkDnsUp(domains[i])
			for {
				nonce, err = funcs.GetNonce(&client, dirResp.NewNonce)
				err = funcs.PostChallenge(&client, chall.Url, nonce, key, kid)
				if err != nil {
					fmt.Println(err)
					time.Sleep(1 * time.Second)
					continue
				} else {
					//stop dns as soon as loaded challenge is completed, wait a bit for clean start of new thread on dns port
					status := "pending"
					for status != "valid" {
						nonce, err = funcs.GetNonce(&client, dirResp.NewNonce)
						status, err = funcs.CheckChallengeStatus(&client, chall.Auth, nonce, key, kid)
						if err != nil {
							time.Sleep(1 * time.Second)
							continue
						}
					}
					stopDns <- true
					time.Sleep(1 * time.Second)
					break
				}
			}
		}
		//set up dns for A records
		go dns.Start(opts.Domains, []string{}, stopDns, false, opts.Record)

	} else if choice == "http01" {
		go httpChall.Start(key_auths, tokens, stopHttp)
		_ = checkHttpUp()
		//set up dns for A records
		go dns.Start(opts.Domains, []string{}, stopDns, dnsServeChall, opts.Record)
		_ = checkDnsUp(opts.Domains[0])
		//time.Sleep(3 * time.Second)
		for _, chall := range filteredChallenges {
			for {
				nonce, err = funcs.GetNonce(&client, dirResp.NewNonce)
				err = funcs.PostChallenge(&client, chall.Url, nonce, key, kid)
				if err != nil {
					time.Sleep(1 * time.Second)
					fmt.Println(err)
				} else {
					//we can respond to challenges in parallel fashion if http
					time.Sleep(1 * time.Second)
					break
				}
			}
		}
	}

	fmt.Println("Waiting for cert...")

	//RFC section 11.1 -> key separation between account key pairs and certs key pairs
	keyCrt, err := ecdsa.GenerateKey(CURVE, rand.Reader)

	status := "pending"
	certificate := ""

	//wait for order to status to go from pending to ready
	for status != "ready" {
		nonce, err = funcs.GetNonce(&client, dirResp.NewNonce)
		status, certificate, err = funcs.PostAsGetOrder(&client, order, nonce, key, kid)
		if err != nil {
			log.Println(err)
			continue
		}
		fmt.Println(status)
		time.Sleep(1 * time.Second)
	}
	fmt.Println("Order is ready...")

	//send POST to Finalize
	//for csr we must use the domains we were passed (i.e those in the identifiers)
	csr, err := makeCSR(opts.Domains, keyCrt)
	if err != nil {
		log.Fatal("Error getting csr")
	}
	for {
		nonce, err = funcs.GetNonce(&client, dirResp.NewNonce)
		err = funcs.PostFinalize(&client, finalize, nonce, key, kid, csr)
		if err != nil {
			log.Println(err)
		} else {
			break
		}
	}

	//check order until status is valid -> i.e certificate url is available
	for status != "valid" {
		nonce, err = funcs.GetNonce(&client, dirResp.NewNonce)
		status, certificate, err = funcs.PostAsGetOrder(&client, order, nonce, key, kid)
		if err != nil {
			log.Println(err)
			continue
		}
		time.Sleep(1 * time.Second)
	}
	fmt.Println("Certificate is available...")

	//POST-as_GET certificate url
	var Cert tls.Certificate
	for {
		nonce, err = funcs.GetNonce(&client, dirResp.NewNonce)
		//certificate, der format(for revocation), error
		Cert, _, err = funcs.PostAsGetCertificate(&client, certificate, nonce, key, kid)
		//fmt.Println(der)
		if err != nil {
			fmt.Println(err)
			continue
		} else {
			fmt.Println("Certificate issued!")
			break
		}
	}
	fmt.Println("Starting TLS server")
	stopTls := make(chan bool)
	go tlsServer.Start(keyCrt, Cert, stopTls)

	if opts.Revoke == true {
		fmt.Println("revoking...")
		for {
			nonce, err = funcs.GetNonce(&client, dirResp.NewNonce)
			der := Cert.Certificate[0]
			err = funcs.PostRevocation(&client, dirResp.RevokeCert, nonce, kid, key, der)
			if err != nil {
				log.Println(err.Error())
				time.Sleep(1 * time.Second)
			} else {
				break
			}
		}
	}
	//wait for termination
	stopClient := make(chan bool)

	go terminator.Start(stopClient)
	//wait...
	<-stopClient
	fmt.Println("Stopping all services")
	stopDns <- true
	if choice == "http01" {
		stopHttp <- true
	}
	stopTls <- true
	fmt.Println("Bye!")
}
