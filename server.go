package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"log"
	"net/http"
	"fmt"
)

func main() {
        certPath := "/etc/ssl/gotest.smartrns.net"
	caCert, err := ioutil.ReadFile("/var/www/api/ca/certs/ca.cert.pem")
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	cfg := &tls.Config{
                ClientAuth: tls.RequestClientCert,
		//ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  caCertPool,
	}
	srv := &http.Server{
		Addr:      ":8443",
		Handler:   &handler{},
		TLSConfig: cfg,
	}
	log.Fatal(srv.ListenAndServeTLS(certPath+"/fullchain.pem", certPath+"/privkey.pem"))
}

type handler struct{}

func (h *handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()
	csr := req.Form.Get("csr")
	fmt.Println(csr)
	csrBytes, _ := pem.Decode([]byte(csr))
	csrParsed, _ := x509.ParseCertificateRequest(csrBytes.Bytes)
	fmt.Println(csrParsed)
	w.Write([]byte("PONG\n"))
}

