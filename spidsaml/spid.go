package spidsaml

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"github.com/beevik/etree"
	"io/ioutil"
	"text/template"

	"github.com/ma314smith/signedxml"
)

// AttributeConsumingService defines, well, an AttributeConsumingService.
type AttributeConsumingService struct {
	ServiceName string
	Attributes  []string
}

// SAMLBinding can be either HTTPRedirect or HTTPPost.
type SAMLBinding string

// Constants for SAMLBinding
const (
	HTTPRedirect SAMLBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	HTTPPost     SAMLBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
)

// SPOrganization Organization adds infos about SP
type SPOrganization struct {
	OrganizationName        string
	OrganizationDisplayName string
	OrganizationURL         string
}

// SPContactPerson ContactPerson metadata
type SPContactPerson struct {
	ContactType     string
	Company         string
	EmailAddress    string
	TelephoneNumber string
	Extensions      []SPContactPersonExtension
}

// SPContactPersonExtension extensions for contact person
type SPContactPersonExtension struct {
	Tag        string
	Value      string
	Extensions []SPContactPersonExtension
}

// SP represents our Service Provider
type SP struct {
	EntityID                   string
	KeyFile                    string
	CertFile                   string
	AssertionConsumerServices  []string
	SingleLogoutServices       map[string]SAMLBinding
	AttributeConsumingServices []AttributeConsumingService
	IDP                        map[string]*IDP
	_cert                      *x509.Certificate
	_key                       *rsa.PrivateKey
	Organization               SPOrganization
	ContactPersons             []SPContactPerson
}

// Session represents an active SPID session.
type Session struct {
	IDPEntityID  string
	NameID       string
	SessionIndex string
	AssertionXML []byte
	Level        int
	Attributes   map[string]string
}

// Cert returns the certificate of this Service Provider.
func (sp *SP) Cert() *x509.Certificate {
	if sp._cert == nil {
		// read file as a byte array
		byteValue, _ := ioutil.ReadFile(sp.CertFile)

		block, _ := pem.Decode(byteValue)
		if block == nil || block.Type != "CERTIFICATE" {
			panic("failed to parse certificate PEM")
		}

		var err error
		sp._cert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			panic(err)
		}
	}
	return sp._cert
}

// Key returns the private key of this Service Provider
func (sp *SP) Key() *rsa.PrivateKey {
	if sp._key == nil {
		// read file as a byte array
		byteValue, _ := ioutil.ReadFile(sp.KeyFile)

		block, _ := pem.Decode(byteValue)
		if block == nil {
			panic("failed to parse private key from PEM file " + sp.KeyFile)
		}

		var err error

		switch block.Type {
		case "RSA PRIVATE KEY":
			sp._key, err = x509.ParsePKCS1PrivateKey(block.Bytes)

		case "PRIVATE KEY":
			var keyOfSomeType interface{}
			keyOfSomeType, err = x509.ParsePKCS8PrivateKey(block.Bytes)
			var ok bool
			sp._key, ok = keyOfSomeType.(*rsa.PrivateKey)
			if !ok {
				err = errors.New("file " + sp.KeyFile + " does not contain an RSA private key")
			}
		default:
			err = errors.New("unknown key type " + block.Type)
		}

		if err != nil {
			panic(err)
		}
	}
	return sp._key
}

// KeyPEM returns the private key of this Service Provider in PEM format
func (sp *SP) KeyPEM() []byte {
	key := sp.Key()
	var block = &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	return pem.EncodeToMemory(block)
}

// GetIDP returns an IDP object representing the Identity Provider matching the given entityID.
func (sp *SP) GetIDP(entityID string) (*IDP, error) {
	if value, ok := sp.IDP[entityID]; ok {
		return value, nil
	}
	return nil, errors.New("IdP not found")
}

// Metadata generates XML metadata of this Service Provider.
func (sp *SP) Metadata(enableSigning bool) string {
	const tmpl = `<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor
    xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
	xmlns:spid="https://spid.gov.it/saml-extensions"
	xmlns:fpa="https://spid.gov.it/invoicing-extensions"
    entityID="{{ .EntityID }}"
    ID="{{ .RandomRequestID }}">

	{{ if .EnableSigning }}
	<ds:Signature>
        <ds:SignedInfo>
            <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
            <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" />
            <ds:Reference URI="#{{ .RandomRequestID }}">
                <ds:Transforms>
                    <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" />
                    <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
                </ds:Transforms>
                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />
                <ds:DigestValue></ds:DigestValue>
            </ds:Reference>
        </ds:SignedInfo>
        <ds:SignatureValue></ds:SignatureValue>
        <ds:KeyInfo>
            <ds:X509Data>
                <ds:X509Certificate>{{ .Cert }}</ds:X509Certificate>
            </ds:X509Data>
        </ds:KeyInfo>
    </ds:Signature>
	{{ end }}

    <md:SPSSODescriptor
        protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"
        AuthnRequestsSigned="true"
        WantAssertionsSigned="true">

        <md:KeyDescriptor use="signing">
            <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                <ds:X509Data>
					<ds:X509SubjectName>{{ .CertSubject }}</ds:X509SubjectName>
                    <ds:X509Certificate>{{ .Cert }}</ds:X509Certificate>
                </ds:X509Data>
            </ds:KeyInfo>
        </md:KeyDescriptor>

        {{ range $url, $binding := .SingleLogoutServices }}
        <md:SingleLogoutService
            Binding="{{ $binding }}"
            Location="{{ $url }}" />
        {{ end }}

        <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>

        {{ range $index, $url := .AssertionConsumerServices }}
        <md:AssertionConsumerService
            Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            Location="{{ $url }}"
            index="{{ $index }}"
            isDefault="{{ if gt $index 0 }}false{{ else }}true{{ end }}" />
        {{ end }}

        {{ range $index, $attcs := .AttributeConsumingServices }}
        <md:AttributeConsumingService index="{{ $index }}">
            <md:ServiceName xml:lang="it">{{ $attcs.ServiceName }}</md:ServiceName>
            {{ range $attr := $attcs.Attributes }}
            <md:RequestedAttribute Name="{{ $attr }}" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/>
            {{ end }}
        </md:AttributeConsumingService>
        {{ end }}

    </md:SPSSODescriptor>

    <md:Organization>
        <md:OrganizationName xml:lang="it">{{ .Organization.OrganizationName }}</md:OrganizationName>
        <md:OrganizationDisplayName xml:lang="it">{{ .Organization.OrganizationDisplayName }}</md:OrganizationDisplayName>
        <md:OrganizationURL xml:lang="it">{{ .Organization.OrganizationURL }}</md:OrganizationURL>
    </md:Organization>

</md:EntityDescriptor>
`
	aux := struct {
		*SP
		Cert            string
		RandomRequestID string
		CertSubject     string
		EnableSigning   bool
	}{
		sp,
		base64.StdEncoding.EncodeToString(sp.Cert().Raw),
		GenerateRandomID(), // Generate a random ID for each request,
		sp.Cert().Subject.String(),
		enableSigning,
	}

	t := template.Must(template.New("metadata").Parse(tmpl))
	var metadata bytes.Buffer

	// Parse now the template
	if t.Execute(&metadata, aux) != nil {
		return ""
	}

	// Add the contact persons to the XML
	completeXML, err := addContactPersons(metadata.String(), sp.ContactPersons)

	if err != nil {
		return ""
	}

	// If the sign is not enabled, just exit here.
	if !enableSigning {
		return completeXML
	}

	// Sign the XML
	signer, err := signedxml.NewSigner(completeXML)

	if err != nil {
		return ""
	}

	completeXML, err = signer.Sign(sp.Key())

	if err != nil {
		return ""
	}

	return completeXML
}

func addContactPersons(signedXML string, persons []SPContactPerson) (string, error) {
	xmlDoc := etree.NewDocument()

	if xmlDoc.ReadFromString(signedXML) != nil {
		return "", nil
	}

	// Get the basic entity descriptor element
	entityDescriptor := xmlDoc.FindElement("EntityDescriptor")

	for _, contactPerson := range persons {
		// Create basic contact person element
		contactPersonXML := entityDescriptor.CreateElement("md:ContactPerson")
		// Add the specified contact type
		contactPersonXML.CreateAttr("contactType", contactPerson.ContactType)

		// Add extensions data
		contactPersonExtensionsXML := contactPersonXML.CreateElement("md:Extensions")

		addContactPersonExtensions(contactPersonExtensionsXML, contactPerson.Extensions)

		// Add company data
		if contactPerson.Company != "" {
			contactPersonXML.CreateElement("md:Company").CreateText(contactPerson.Company)
		}

		// Add email address data
		if contactPerson.EmailAddress != "" {
			contactPersonXML.CreateElement("md:EmailAddress").CreateText(contactPerson.EmailAddress)
		}

		// Add telephone number data
		if contactPerson.TelephoneNumber != "" {
			contactPersonXML.CreateElement("md:TelephoneNumber").CreateText(contactPerson.TelephoneNumber)
		}
	}

	return xmlDoc.WriteToString()
}

func addContactPersonExtensions(xml *etree.Element, extensions []SPContactPersonExtension) {

	for _, extension := range extensions {
		xmlElement := xml.CreateElement(extension.Tag)

		if extension.Value != "" {
			xmlElement.CreateText(extension.Value)
		}

		if len(extension.Extensions) > 0 {
			addContactPersonExtensions(xmlElement, extension.Extensions)
		}
	}
}
