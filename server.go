package main

import (
	"crypto/tls"
	"crypto/x509"
//	"crypto/x509/pkix"
	"crypto/rand"
//	"encoding/asn1"
	"encoding/pem"
	"io/ioutil"
	"log"
	"net/http"
	"fmt"
	"time"
	"math/big"
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
	caKey, err := ioutil.ReadFile("/var/www/api/ca/private/dec.ca.key.pem")
	fmt.Println(err)
	caKeyBytes, _ := pem.Decode([]byte(caKey))
	var caKeyPriv interface{}
	//caKeyPriv, _ := x509.ParsePKCS8PrivateKey(caKeyBytes.Bytes)
	caKeyPriv, err = x509.ParsePKCS1PrivateKey(caKeyBytes.Bytes)
	fmt.Println(err)
	caKeyPubPEM, err := ioutil.ReadFile("/var/www/api/ca/private/pub.ca.pem")
	caKeyPubBytes, _ := pem.Decode([]byte(caKeyPubPEM))
	caKeyPub, err := x509.ParsePKIXPublicKey(caKeyPubBytes.Bytes)
	fmt.Println(err)
	fmt.Println("readcert")
	caCert, err := ioutil.ReadFile("/var/www/api/ca/certs/ca2.cert.pem")
	fmt.Println(caCert)
	fmt.Println(err)
	caCertBytes, _ := pem.Decode([]byte(caCert))
	caCertParsed, err := x509.ParseCertificate(caCertBytes.Bytes)
	fmt.Println(err)

	clientCSR := csrParsed
	caCRT := caCertParsed

	fmt.Println("A")

	//extSubjectAltName := pkix.Extension{
	//	Id: asn1.ObjectIdentifier{2, 5, 29, 17},
	//	Critical: false,
	//	Value: []byte(`email:my@mail.tld, URI:http://ca.dom.tld/`),
	//}



	clientCRTTemplate := x509.Certificate{
		Signature:          clientCSR.Signature,
		SignatureAlgorithm: clientCSR.SignatureAlgorithm,
		PublicKeyAlgorithm: clientCSR.PublicKeyAlgorithm,
		PublicKey:          clientCSR.PublicKey,
		SerialNumber: big.NewInt(5),
		Issuer:       caCRT.Subject,
		Subject:      clientCSR.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{"san1.srns.local", "san2.srns.local"},
		//ExtraExtensions: []pkix.Extension{extSubjectAltName},
		//Extensions: []pkix.Extension{extSubjectAltName},

	}

	fmt.Println("B")
	fmt.Println(caKeyPub)


	//derBytes, err := x509.CreateCertificate(rand.Reader, &clientCRTTemplate, caCertParsed, caKeyPub, caKeyPriv)
	derBytes, err := x509.CreateCertificate(rand.Reader, &clientCRTTemplate, caCertParsed, clientCSR.PublicKey, caKeyPriv)
	fmt.Println("C")
	fmt.Println(err)
	crtPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	fmt.Println(crtPem)
	w.Write([]byte(crtPem))
	//w.Write([]byte("PONG\n"))
}

