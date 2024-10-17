package spidsaml

import (
	"bytes"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

func TestInMessage_validateSignatureForPost(t *testing.T) {
	firstBytesOfSignature := []byte("ocC")
	cases := []struct {
		testClock *dsig.Clock
		xml       []byte
		returnErr bool
		name      string
	}{
		{
			testClock: dsig.NewFakeClockAt(time.Date(2021, time.Month(3), 18, 16, 37, 0, 0, time.UTC)),
			xml:       createTestXml(),
			returnErr: false,
			name:      "Can recognize a valid signed document",
		},
		{
			xml:       bytes.Replace(createTestXml(), firstBytesOfSignature, []byte("xxx"), 1),
			returnErr: true,
			name:      "Can recognize an invalid signed document",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sp := createSPForTes()
			sp.LoadIDPsFromXMLFile("../sample_data/test_idp/testenv2_metadata.xml")
			msg := inMessage{
				protocolMessage: protocolMessage{
					SP:    sp,
					IDP:   sp.IDP["http://localhost:8088"],
					clock: tc.testClock,
				}}

			msg.SetXML(tc.xml)

			err := msg.validateSignatureForPost(msg.doc.Root())

			if err != nil && !tc.returnErr {
				t.Error("Failed to validate response with error ", err)
			}

			if err == nil && tc.returnErr {
				t.Error("Verification should fail")
			}
		})
	}
}

func TestParseSignatureTag_with_namespace(t *testing.T) {
	doc := etree.NewDocument()
	err := doc.ReadFromFile("../sample_data/idp_metadata/aruba.xml")
	if err != nil {
		t.Error("failed to parse sample XML file")
	}

	sigEl := doc.FindElement("//Signature[namespace-uri()='http://www.w3.org/2000/09/xmldsig#']")
	if sigEl == nil {
		t.Error("signature element not found")
	}
}

// Poste returns <Signature xmlns="..."> tags instead of using the ds: namespace
func TestParseSignatureTag_no_namespace(t *testing.T) {
	doc := etree.NewDocument()
	doc.ReadFromBytes([]byte(`
<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<saml2p:Response
    xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" Destination="https://www.example.com" ID="_56ea979d-779b-4cec-9aaf-2352e62343ec" InResponseTo="_fdead8caebc703fb723eecb585eeee60" IssueInstant="2024-10-17T18:15:59.461Z" Version="2.0">
    <saml2:Issuer
        xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">https://posteid.poste.it
    </saml2:Issuer>
    <Signature
        xmlns="http://www.w3.org/2000/09/xmldsig#">
        <SignedInfo>
            <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
            <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
            <Reference URI="#_56ea979d-779b-4cec-9aaf-2352e62343ec">
                <Transforms>
                    <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                    <Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                </Transforms>
                <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                <DigestValue>3D9/EjqUEGl6Yi1KAqXnetyn3HQs7Pjww8SQAKUhftU=</DigestValue>
            </Reference>
        </SignedInfo>
        <SignatureValue>foobar</SignatureValue>
        <KeyInfo>
            <X509Data>
                <X509Certificate>foobar</X509Certificate>
            </X509Data>
        </KeyInfo>
    </Signature>
    <saml2p:Status>
        <saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </saml2p:Status>
    <saml2:Assertion
        xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_40e3237a-779a-42e3-95c2-b1c2d6a4b70d" IssueInstant="2024-10-17T18:15:58.461Z" Version="2.0">
        <saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">https://posteid.poste.it</saml2:Issuer>
        <Signature
            xmlns="http://www.w3.org/2000/09/xmldsig#">
            <SignedInfo>
                <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                <Reference URI="#_40e3237a-779a-42e3-95c2-b1c2d6a4b70d">
                    <Transforms>
                        <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                        <Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                    </Transforms>
                    <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                    <DigestValue>GmwJV2AGzZAcej+nR/aBbzyjJCGJoY7UDa6dZyi4jFs=</DigestValue>
                </Reference>
            </SignedInfo>
            <SignatureValue>foobar</SignatureValue>
            <KeyInfo>
                <X509Data>
                    <X509Certificate>foobar</X509Certificate>
                </X509Data>
            </KeyInfo>
        </Signature>
    </saml2:Assertion>
</saml2p:Response>
	`))

	sigEl := doc.FindElement("//Signature[namespace-uri()='http://www.w3.org/2000/09/xmldsig#']")
	if sigEl == nil {
		t.Error("signature element not found")
	}
}
