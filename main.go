package main

import (
	"bytes"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"

	"github.com/antchfx/xmlquery"
	"github.com/spf13/pflag"
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

func isURL(str string) bool {
	u, err := url.Parse(str)
	return err == nil && u.Scheme != "" && u.Host != ""
}

func isFile(str string) bool {
	_, err := os.Stat(str)
	return err == nil
}

func getXMLFromFile(filename string) (*xmlquery.Node, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	doc, err := xmlquery.Parse(f)
	if err != nil {
		return nil, err
	}

	return doc, nil
}

func getXMLFromURL(url string) (*xmlquery.Node, error) {
	return xmlquery.LoadURL(url)
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
	pflag.StringVarP(&outFileName, "write", "w", "", "Output file name")
	pflag.Parse()

	args := pflag.Args()
	if len(args) != 1 {
		fmt.Println("Usage: samlmeta <filename>")
		os.Exit(1)
	}

	arg := args[0]
	var doc *xmlquery.Node
	var err error

	if isURL(arg) {
		doc, err = getXMLFromURL(arg)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	} else if isFile(arg) {
		doc, err = getXMLFromFile(arg)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	} else {
		fmt.Println("Invalid filename/URL")
		os.Exit(1)
	}

	// Get the sign-in certificate
	certs := xmlquery.Find(doc, "//*[local-name(.)='EntityDescriptor']/*[local-name(.)='IDPSSODescriptor']/*[local-name(.)='KeyDescriptor' and @use='signing']/*[local-name(.)='KeyInfo' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']/*[local-name(.)='X509Data']/*[local-name(.)='X509Certificate']/text()")
	for _, certData := range certs {
		cert := certToPEM(certData.Data)
		fmt.Printf("Sign-in Certificate (PEM):\n%s\n", cert)
	}

	if len(certs) > 1 {
		fmt.Println("WARNING: More than one signing certificates found!\n")
	}

	// Get the Sign-in URL
	signin := xmlquery.FindOne(doc, "//*[local-name(.)='EntityDescriptor']/*[local-name(.)='IDPSSODescriptor']/*[local-name(.)='SingleSignOnService']")
	if signin != nil {
		fmt.Printf("Sign-in URL:\n%s\n", signin.SelectAttr("Location"))
	}

	cert := certToPEM(certs[0].Data)
	if outFileName != "" {
		writeCertToFile(outFileName, cert)
	}
}
