package main

import (
	"bytes"
	"encoding/base64"
	"encoding/pem"
	"flag"
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

func writeCertToFile(filename, cert string) {
	if err := os.WriteFile(filename, []byte(cert), 0644) ; err != nil {
		fmt.Println("Error writing file")
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Printf("Wrote certificate to %s\n", filename)
}

func main() {
	var outFileName string
	flag.StringVar(&outFileName, "w", "", "Output file name")
	flag.Parse()

	args := flag.Args()
	if len(args) != 1 {
		fmt.Println("Usage: samlmeta <filename>")
		os.Exit(1)
	}

	filename := args[0]
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
	certData := xmlquery.FindOne(doc, "//*[local-name(.)='EntityDescriptor']/*[local-name(.)='IDPSSODescriptor']/*[local-name(.)='KeyDescriptor' and @use='signing']/*[local-name(.)='KeyInfo' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']/*[local-name(.)='X509Data']/*[local-name(.)='X509Certificate']/text()")
	cert := certToPEM(certData.Data)
	fmt.Printf("Sign-in Certificate (PEM):\n%s\n", cert)

	// Get the Sign-in URL
	signin := xmlquery.FindOne(doc, "//SingleSignOnService[@Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST']")
	if signin != nil {
		fmt.Printf("Sign-in URL:\n%s\n", signin.SelectAttr("Location"))
	}

	if outFileName != "" {
		writeCertToFile(outFileName, cert)
	}
}
