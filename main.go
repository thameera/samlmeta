package main

import (
	"bytes"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/antchfx/xmlquery"
)

func certToPEM(cert string) string {
	decoded, err := base64.StdEncoding.DecodeString(cert)
	if err != nil {
		fmt.Println(err)
		return ""
	}
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte(decoded),
	}

	var pemData bytes.Buffer
	pem.Encode(&pemData, block)
	return pemData.String()
}

func main() {
	if len(os.Args) < 2 || len(os.Args) > 2 {
		fmt.Println("Usage: samlmeta <filename>")
		return
	}

	filename := os.Args[1]
	f, err := os.Open(filename)
	if err != nil {
		fmt.Println(err)
		return
	}

	doc, err := xmlquery.Parse(f)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Get the sign-in certificate
	cert := xmlquery.FindOne(doc, "//*[local-name(.)='EntityDescriptor']/*[local-name(.)='IDPSSODescriptor']/*[local-name(.)='KeyDescriptor' and @use='signing']/*[local-name(.)='KeyInfo' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']/*[local-name(.)='X509Data']/*[local-name(.)='X509Certificate']/text()")
	fmt.Printf("Sign-in Certificate (PEM):\n%s\n", certToPEM(cert.Data))

	// Get the Sign-in URL
	signin := xmlquery.FindOne(doc, "//SingleSignOnService[@Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST']")
	if signin != nil {
		fmt.Printf("Sign-in URL:\n%s", signin.SelectAttr("Location"))
	}

}
