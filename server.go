package main

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {

	certPath := "/etc/ssl/gotest.smartrns.net"
	//caCert, err := ioutil.ReadFile("/var/www/api/ca/certs/ca.cert.pem")
	caCert, err := ioutil.ReadFile("/var/www/api/ca/certs/ca-root.pem")
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	cfg := &tls.Config{
		//ClientAuth: tls.RequestClientCert,
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  caCertPool,
		//RootCAs:  caCertPool,
	}
	h := handler{}
	h.SetCAKey("/var/www/api/ca/private/dec.ca.key.pem")
	h.SetCACert("/var/www/api/ca/certs/ca-root.pem")
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGHUP)
	go func() {
		for sig := range c {
			println(sig)
			fmt.Printf("Got A HUP Signal! Now Reloading Conf....\n")
			//h.SetCAKey("/var/www/api/ca/private/dec.ca.key.pem")
			h.SetCAKey("sigsso_private.key")
			h.SetCACert("/var/www/api/ca/certs/ca.cert.pem")
		}
	}()
	srv := &http.Server{
		Addr:      ":8443",
		Handler:   &h,
		TLSConfig: cfg,
	}
	log.Fatal(srv.ListenAndServeTLS(certPath+"/fullchain.pem", certPath+"/privkey.pem"))
}

type handler struct {
	caKeyPriv interface{}
	caCert    *x509.Certificate
}

func (h *handler) SetCAKey(filename string) {
	caKey, _ := ioutil.ReadFile(filename)
	caKeyBytes, _ := pem.Decode([]byte(caKey))
	h.caKeyPriv, _ = x509.ParsePKCS1PrivateKey(caKeyBytes.Bytes)
	fmt.Printf("Loaded CA key: %s\n", filename)
}

func (h *handler) SetCACert(filename string) {
	caCert, _ := ioutil.ReadFile(filename)
	caCertBytes, _ := pem.Decode([]byte(caCert))
	h.caCert, _ = x509.ParseCertificate(caCertBytes.Bytes)
	fmt.Printf("Loaded CA cert: %s\n", filename)
}

func (h *handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {

	req.ParseForm()
	csr := req.Form.Get("csr")
	peerCerts := req.TLS.PeerCertificates
	dbg2, err := json.Marshal(peerCerts)
	fmt.Println(err)
	fmt.Println(string(dbg2))
	fmt.Println(peerCerts[0].DNSNames)
	csrBytes, _ := pem.Decode([]byte(csr))
	csrParsed, _ := x509.ParseCertificateRequest(csrBytes.Bytes)
	clientCSR := csrParsed
	caCRT := h.caCert

	peerDNSNames := peerCerts[0].DNSNames
	clientDNSNames := clientCSR.DNSNames
	fmt.Println(clientDNSNames)
	if ok, name := IsSubset(clientDNSNames, peerDNSNames); !ok {
		fmt.Printf("DNS name not authorized by client certificate: %s\n", name)
		return
	}

	//extSubjectAltName := pkix.Extension{
	//	Id: asn1.ObjectIdentifier{2, 5, 29, 17},
	//	Critical: false,
	//	Value: []byte(`email:my@mail.tld, URI:http://ca.dom.tld/`),
	//}
	dbg, _ := json.Marshal(clientCSR)
	fmt.Println(string(dbg))
	fmt.Println(clientCSR.DNSNames)

	clientCRTTemplate := x509.Certificate{
		Signature:          clientCSR.Signature,
		SignatureAlgorithm: clientCSR.SignatureAlgorithm,
		PublicKeyAlgorithm: clientCSR.PublicKeyAlgorithm,
		PublicKey:          clientCSR.PublicKey,
		SerialNumber:       big.NewInt(6),
		Issuer:             caCRT.Subject,
		Subject:            clientCSR.Subject,
		NotBefore:          time.Now(),
		NotAfter:           time.Now().Add(24 * time.Hour),
		KeyUsage:           x509.KeyUsageDigitalSignature,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		DNSNames:           clientCSR.DNSNames,
		//ExtraExtensions: []pkix.Extension{extSubjectAltName},
		//Extensions: []pkix.Extension{extSubjectAltName},

	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &clientCRTTemplate, h.caCert, clientCSR.PublicKey, h.caKeyPriv)
	fmt.Println(err)
	crtPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	//fmt.Println(crtPem)
	w.Write([]byte(crtPem))
}

func IsSubset(x, y []string) (bool, string) {
	set := make(map[string]bool)
	for _, v := range y {
		set[v] = true
	}
	for _, v := range x {
		if _, found := set[v]; !found {
			return false, v
		}
	}
	return true, ""
}
