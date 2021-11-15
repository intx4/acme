package dns

import (
	"crypto/sha256"
	b64 "encoding/base64"
	"fmt"
	"net"
	"strconv"

	"github.com/miekg/dns"
)

type handler struct {
	records  map[string]string
	key_auth map[string]string //_acme-challenge.domain -> b64url(sha256(keyauth))
}

func NewHandler() handler {
	var h handler
	h.records = make(map[string]string)
	h.key_auth = make(map[string]string)
	return h
}

func (h *handler) AddRecords(domains []string, record string, key_auth []string, dnsServeChall bool) {

	for i, domain := range domains {
		h.records[domain+"."] = record
		if dnsServeChall == true {
			digest := sha256.Sum256([]byte(key_auth[i]))
			h.key_auth["_acme-challenge"+"."+domain+"."] = b64.RawURLEncoding.EncodeToString(digest[:])
		}
	}
}

func (h *handler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	msg := dns.Msg{}
	msg.SetReply(r)
	switch r.Question[0].Qtype {
	case dns.TypeA:
		fmt.Println("DNS A")
		fmt.Println(r)
		msg.Authoritative = true
		msg.Rcode = dns.RcodeSuccess
		domain := msg.Question[0].Name
		_, ok := h.records[domain]
		if ok {
			msg.Answer = append(msg.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
				A:   net.ParseIP(h.records[domain]),
			})
			fmt.Println(msg.Answer)
			w.WriteMsg(&msg)
		}
	case dns.TypeAAAA:
		fmt.Println("DNS AAAA")
		fmt.Println(r)
		msg.Authoritative = true
		msg.Rcode = dns.RcodeSuccess
		domain := msg.Question[0].Name
		_, ok := h.records[domain]
		if ok {
			msg.Answer = append(msg.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
				A:   net.ParseIP(h.records[domain]),
			})
			fmt.Println(msg.Answer)
			w.WriteMsg(&msg)
		}
	case dns.TypeTXT:
		fmt.Println("DNS query TXT")
		fmt.Println(r)
		msg.Authoritative = true
		msg.Rcode = dns.RcodeSuccess
		domain := msg.Question[0].Name
		_, ok := h.key_auth[domain]
		if ok {
			var txt []string
			txt = append(txt, h.key_auth[domain])
			msg.Answer = append(msg.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
				Txt: txt,
			})
			w.WriteMsg(&msg)
		}
	}
}

func Start(domains []string, key_auth []string, stopDns chan bool, dnsServeChall bool, record string) {
	port := 10053
	server := &dns.Server{Addr: ":" + strconv.Itoa(port), Net: "udp"}
	h := NewHandler()
	h.AddRecords(domains, record, key_auth, dnsServeChall)
	server.Handler = &h
	go server.ListenAndServe()
	<-stopDns
	server.Shutdown()
}
