package spidsaml

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/beevik/etree"
)

// IDP represents an Identity Provider.
type IDP struct {
	XML        string
	EntityID   string
	Certs      []*x509.Certificate
	SSOURLs    map[SAMLBinding]string
	SLOReqURLs map[SAMLBinding]string
	SLOResURLs map[SAMLBinding]string
}

// ParseIDPsFromXML takes XML metadata and returns an IDP object.
func ParseIDPsFromXML(xml []byte) ([]*IDP, error) {
	doc := etree.NewDocument()
	err := doc.ReadFromBytes(xml)
	if err != nil {
		return nil, err
	}

	var idps []*IDP

	for _, idpEl := range doc.FindElements("//EntityDescriptor") {
		idp := new(IDP)
		idp.EntityID = idpEl.SelectAttr("entityID").Value

		// TODO: if metadata is signed, validate /md:EntityDescriptor/dsig:Signature
		// against a known CA

		// SingleSignOnService
		idp.SSOURLs = make(map[SAMLBinding]string)
		for _, e := range idpEl.FindElements("./IDPSSODescriptor/SingleSignOnService") {
			idp.SSOURLs[SAMLBinding(e.SelectAttr("Binding").Value)] = e.SelectAttr("Location").Value
		}

		// SingleLogoutService
		idp.SLOReqURLs = make(map[SAMLBinding]string)
		idp.SLOResURLs = make(map[SAMLBinding]string)
		for _, e := range idpEl.FindElements("./IDPSSODescriptor/SingleLogoutService") {
			binding := SAMLBinding(e.SelectAttr("Binding").Value)
			idp.SLOReqURLs[binding] = e.SelectAttr("Location").Value
			resloc := e.SelectAttr("ResponseLocation")
			if resloc != nil {
				idp.SLOResURLs[binding] = resloc.Value
			} else {
				idp.SLOResURLs[binding] = e.SelectAttr("Location").Value
			}
		}

		// certificate
		certs := idpEl.FindElements("./IDPSSODescriptor/KeyDescriptor[@use='signing']/KeyInfo/X509Data/X509Certificate")
		nrOfCertificates := len(certs)
		if nrOfCertificates == 0 {
			return nil, fmt.Errorf("could not read certificate for IdP with entityID: %v", idp.EntityID)
		}

		idp.Certs = make([]*x509.Certificate, nrOfCertificates)

		for i, cert := range certs {
			// remove whitespace
			certText := cert.Text()
			certText = strings.Replace(certText, " ", "", -1)
			certText = strings.Replace(certText, "\n", "", -1)
			certText = strings.Replace(certText, "\t", "", -1)

			data, err := base64.StdEncoding.DecodeString(certText)
			if err != nil {
				return nil, fmt.Errorf("failed to decode base64 certificate for IdP with entityID %s: %w", idp.EntityID, err)
			}
			idp.Certs[i], err = x509.ParseCertificate(data)
			if err != nil {
				return nil, fmt.Errorf("failed to parse certificate for IdP with entityID %s: %w", idp.EntityID, err)
			}
		}

		idps = append(idps, idp)
	}

	return idps, nil
}

// LoadIDPsFromXMLFile loads an Identity Provider from its XML metadata.
func (sp *SP) LoadIDPsFromXMLFile(path string) error {
	// read the XML file
	byteValue, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	// load the IdP(s) contained in the XML file
	idps, err := ParseIDPsFromXML(byteValue)
	if err != nil {
		return err
	}

	// store the loaded IdP
	if sp.IDP == nil {
		sp.IDP = make(map[string]*IDP)
	}
	for _, idp := range idps {
		sp.IDP[idp.EntityID] = idp
	}

	return nil
}

// LoadIDPMetadata load one or multiple Identity Providers by reading all the XML files in the given directory.
func (sp *SP) LoadIDPMetadata(dir string) error {
	files, err := filepath.Glob(dir + "/*.xml")
	if err != nil {
		log.Fatal(err)
	}

	for _, file := range files {
		err := sp.LoadIDPsFromXMLFile(file)
		if err != nil {
			return err
		}
	}

	return nil
}

// CertPEM returns the IdP certificate in PEM format.
func (idp *IDP) CertPEM() [][]byte {
	nrOfCertificates := len(idp.Certs)
	result := make([][]byte, nrOfCertificates)
	for i, cert := range idp.Certs {
		result[i] = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	}
	return result
}
