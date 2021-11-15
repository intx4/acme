package terminator

import (
	"log"
	"net/http"
)

type handler struct {
	Shutdown chan bool
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	//log.Println(r)
	//w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	h.Shutdown <- true
}

func Start(stopClient chan bool) {

	h := new(handler)
	h.Shutdown = make(chan bool)
	http.Handle("/shutdown", h)

	go http.ListenAndServe(":5003", nil)
	<-h.Shutdown
	log.Println("Shutdown...")
	stopClient <- true
}
