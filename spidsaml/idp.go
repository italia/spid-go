package spidsaml

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
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

// NewIDPFromXML takes XML metadata and returns an IDP object.
func NewIDPFromXML(xml []byte) *IDP {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xml); err != nil {
		panic(err)
	}

	// TODO: if metadata is signed, validate /md:EntityDescriptor/dsig:Signature
	// against a known CA

	idp := new(IDP)
	idp.EntityID = doc.FindElement("/EntityDescriptor").SelectAttr("entityID").Value

	// SingleSignOnService
	idp.SSOURLs = make(map[SAMLBinding]string)
	for _, e := range doc.FindElements("/EntityDescriptor/IDPSSODescriptor/SingleSignOnService") {
		idp.SSOURLs[SAMLBinding(e.SelectAttr("Binding").Value)] = e.SelectAttr("Location").Value
	}

	// SingleLogoutService
	idp.SLOReqURLs = make(map[SAMLBinding]string)
	idp.SLOResURLs = make(map[SAMLBinding]string)
	for _, e := range doc.FindElements("/EntityDescriptor/IDPSSODescriptor/SingleLogoutService") {
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
	certs := doc.FindElements("/EntityDescriptor/IDPSSODescriptor/KeyDescriptor[@use='signing']/KeyInfo/X509Data/X509Certificate")
	nrOfCertificates := len(certs)
	if nrOfCertificates == 0 {
		panic(fmt.Sprintf("Could not read certificate for IdP with entityID: %v\n", idp.EntityID))
	}

	idp.Certs = make([]*x509.Certificate, nrOfCertificates)

	for i, cert := range certs  {
		// remove whitespace
		certText := cert.Text()
		certText = strings.Replace(certText, " ", "", -1)
		certText = strings.Replace(certText, "\n", "", -1)
		certText = strings.Replace(certText, "\t", "", -1)

		data, err := base64.StdEncoding.DecodeString(certText)
		if err != nil {
			panic(fmt.Sprintf("failed to decode base64 certificate: %s", err))
		}
		idp.Certs[i], err = x509.ParseCertificate(data)
		if err != nil {
			panic("failed to parse certificate: " + err.Error())
		}
	}

	return idp
}

// LoadIDPFromXMLFile loads an Identity Provider from its XML metadata.
func (sp *SP) LoadIDPFromXMLFile(path string) error {

	idp, err := LoadIDPFrom(path)

	if err != nil {
		return nil
	}

	// store the loaded IdP
	if sp.IDP == nil {
		sp.IDP = make(map[string]*IDP)
	}
	sp.IDP[idp.EntityID] = idp

	return nil
}

func LoadIDPFrom(path string) (*IDP, error) {
	// open XML file
	xmlFile, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer xmlFile.Close()

	// read our opened xmlFile as a byte array.
	byteValue, err := ioutil.ReadAll(xmlFile)
	if err != nil {
		return nil, err
	}

	// load the IdP
	idp := NewIDPFromXML(byteValue)

	return idp, nil
}

// LoadIDPMetadata load one or multiple Identity Providers by reading all the XML files in the given directory.
func (sp *SP) LoadIDPMetadata(dir string) error {
	files, err := filepath.Glob(dir + "/*.xml")
	if err != nil {
		log.Fatal(err)
	}

	for _, file := range files {
		err := sp.LoadIDPFromXMLFile(file)
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
