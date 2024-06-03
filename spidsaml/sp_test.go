package spidsaml

import (
	"crypto/rsa"
	"crypto/x509"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"github.com/crewjam/go-xmlsec"
)

func TestSP_Key(t *testing.T) {
	cases := []struct {
		keyFile   string
		returnErr bool
		name      string
	}{
		{
			keyFile:   "non_existing_file.pem",
			returnErr: true,
			name:      "Gives error when key file does not exist",
		},
		{
			keyFile:   "../sample_data/key.rsa.pem",
			returnErr: false,
			name:      "Can read a key in PKS1 format",
		},
		{
			keyFile:   "../sample_data/key.pem",
			returnErr: false,
			name:      "Can read a key in PKS8 format",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := readKey(tc.keyFile)
			returnedErr := err != nil

			if returnedErr != tc.returnErr {
				t.Fail()
			}
		})
	}
}

func TestSP_Cert(t *testing.T) {
	cases := []struct {
		certFile  string
		returnErr bool
		name      string
	}{
		{
			certFile:  "non_existing_file.pem",
			returnErr: true,
			name:      "Gives error when certificate file does not exist",
		},
		{
			certFile:  "../sample_data/crt.pem",
			returnErr: false,
			name:      "Can read a certificate file",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := readCert(tc.certFile)
			returnedErr := err != nil

			if returnedErr != tc.returnErr {
				t.Fail()
			}
		})
	}
}

func TestSP_Metadata(t *testing.T) {
	sp := createSPForTes()
	cases := []struct {
		attribute string
		name      string
	}{
		{
			attribute: `entityID="https://spid.comune.roma.it"`,
			name:      "Contains the right entityID",
		},
	}
	metadata := sp.Metadata()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(metadata, tc.attribute) {
				t.Fail()
			}
		})
	}
}

func TestSP_MetadataOrganization(t *testing.T) {
	sp := createSPForTes()
	doc := etree.NewDocument()
	if doc.ReadFromString(sp.Metadata()) != nil {
		panic("error occurred during parsing metadata file")
	}

	testCases := []struct {
		name        string
		entityPath  string
		entityValue []string
	}{
		{
			name:        "Organization name",
			entityPath:  "/EntityDescriptor/Organization/OrganizationName",
			entityValue: []string{"Comune di Roma"},
		},
		{
			name:        "Organization display name",
			entityPath:  "/EntityDescriptor/Organization/OrganizationDisplayName",
			entityValue: []string{"Comune di Roma"},
		},
		{
			name:        "Organization URL",
			entityPath:  "/EntityDescriptor/Organization/OrganizationURL",
			entityValue: []string{"https://comune.roma.it"},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for _, e := range doc.FindElements(tc.entityPath) {
				if !contains(tc.entityValue, e.Text()) {
					t.Fail()
				}
			}
		})
	}
}

func TestSP_KeyPEM(t *testing.T) {
	sp := createSPForTes()

	xml := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<Envelope xmlns="urn:envelope">
  <Data>
	Hello, World!
  </Data>
  <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
    <SignedInfo>
      <CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315" />
      <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1" />
      <Reference URI="">
        <Transforms>
          <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" />
        </Transforms>
        <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" />
        <DigestValue></DigestValue>
      </Reference>
    </SignedInfo>
    <SignatureValue/>
    <KeyInfo>
	<KeyName/>
    </KeyInfo>
  </Signature>
</Envelope>`)

	doc := etree.NewDocument()
	doc.ReadFromBytes(xml)

	signatureOptions := xmlsec.SignatureOptions{}

	signedDoc, errSign := xmlsec.Sign(sp.KeyPEM(), xml, signatureOptions)

	if errSign != nil {
		t.Error("Error during signing phase:", errSign)
	}

	errVerify := xmlsec.Verify(sp.CertPEM(), signedDoc, signatureOptions)

	if errVerify != nil {
		t.Error("Error during verifing phase", errVerify)
	}
}

func createSPForTes() *SP {
	return &SP{
		EntityID: "https://spid.comune.roma.it",
		KeyFile:  "../sample_data/key.pem",
		CertFile: "../sample_data/crt.pem",
		AssertionConsumerServices: []string{
			"http://localhost:8000/spid-sso",
		},
		SingleLogoutServices: map[string]SAMLBinding{
			"http://localhost:8000/spid-slo": HTTPRedirect,
		},
		AttributeConsumingServices: []AttributeConsumingService{
			{
				ServiceName: "Service 1",
				Attributes:  []string{"fiscalNumber", "name", "familyName", "dateOfBirth"},
			},
		},
		Organization: Organization{
			Names:        []string{"Comune di Roma"},
			DisplayNames: []string{"Comune di Roma"},
			URLs:         []string{"https://comune.roma.it"},
		},
	}
}

func readCert(certFile string) (key *x509.Certificate, err interface{}) {
	defer func() {
		err = recover()
	}()
	sp := &SP{
		CertFile: certFile,
	}
	return sp.Cert(), nil
}

func readKey(keyFile string) (key *rsa.PrivateKey, err interface{}) {
	defer func() {
		err = recover()
	}()
	sp := &SP{
		KeyFile: keyFile,
	}
	return sp.Key(), nil
}

func contains(array []string, value string) bool {
	for _, el := range array {
		if el == value {
			return true
		}
	}
	return false
}
