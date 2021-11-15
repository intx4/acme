package tlsServer

import (
	"crypto/ecdsa"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
)

type handler struct {
	//pass
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Println("HTTPS request received")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
}

func Start(key *ecdsa.PrivateKey, cert tls.Certificate, stopTls chan bool) {
	cert.PrivateKey = key
	config := &tls.Config{Certificates: []tls.Certificate{cert}}
	ln, err := tls.Listen("tcp", ":5001", config)

	if err != nil {
		log.Println(err)
		return
	}

	h := new(handler)
	go http.Serve(ln, h)
	<-stopTls
	ln.Close()
}
