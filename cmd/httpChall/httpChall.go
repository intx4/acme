package httpChall

import (
	"fmt"
	"io"
	"net/http"
)

type handler struct {
	key_auth string
	test     bool
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.test == false {
		fmt.Println("HTTP chall received")
		w.Header().Set("Content-Type", "application/octet-stream")
		io.WriteString(w, h.key_auth)
		//w.WriteHeader(http.StatusOK)
	} else {
		io.WriteString(w, "ok")
	}
}

func Start(key_auth []string, tokens []string, stopHttp chan bool) {
	for i, token := range tokens {
		h := &handler{key_auth[i], false}
		http.Handle("/.well-known/acme-challenge/"+token, h)
	}
	t := &handler{"", true}
	http.Handle("/test", t)

	go http.ListenAndServe(":5002", nil)
	<-stopHttp
}
