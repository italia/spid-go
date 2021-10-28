package spidsaml

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"text/template"
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

// SPContactPerson ContactPerson metadata about sp full
type SPContactPerson struct {
	ContactType      string
	EntityType       string
	IpaCode          string
	VatNumber        string
	FiscalCode       string
	Company          string
	EmailAddress     string
	TelephoneNumber  string
	IsFullAggregator bool
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
		if block == nil || block.Type != "RSA PRIVATE KEY" {
			panic("failed to parse private key from PEM file")
		}

		var err error
		sp._key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
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
func (sp *SP) Metadata() string {
	const tmpl = `<?xml version="1.0"?>
<md:EntityDescriptor
    xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
    entityID="{{.EntityID}}"
    ID="_681a637-6cd4-434f-92c3-4fed720b2ad8">

    <md:SPSSODescriptor
        protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"
        AuthnRequestsSigned="true"
        WantAssertionsSigned="true">

        <md:KeyDescriptor use="signing">
            <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                <ds:X509Data>
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

	{{ range $index, $contact := .ContactPersons }}
	<md:ContactPerson contactType="{{ $contact.ContactType }}" spid:entityType="{{ $contact.EntityType }}"> 
		<md:Extensions> 
			{{ if ne $contact.IpaCode nil and ne $contact.IpaCode "" }}
			<spid:IPACode>{{ $contact.IpaCode }}</spid:IPACode>
			{{ end }}
			{{ if ne $contact.VatNumber nil and ne $contact.VatNumber "" }}
			<spid:VATNumber>{{ $contact.VatNumber }}</spid:VATNumber>
			{{ end }}
			{{ if ne $contact.FiscalCode nil and ne $contact.FiscalCode "" }}
            <spid:FiscalCode>{{ $contact.FiscalCode }}</spid:FiscalCode>
			{{ end }}
			{{ if $contact.IsFullAggregator }}
            <spid:PublicServicesFullOperator/>
			{{ end }}
        </md:Extensions> 
        <md:Company>{{ $contact.Company }}</md:Company> 
        <md:EmailAddress>{{ $contact.Email }}</md:EmailAddress> 
        <md:TelephoneNumber>{{ $contact.TelephoneNumber }}</md:TelephoneNumber> 
    </md:ContactPerson>
	{{ end }}

</md:EntityDescriptor>
`
	aux := struct {
		*SP
		Cert string
	}{
		sp,
		base64.StdEncoding.EncodeToString(sp.Cert().Raw),
	}

	t := template.Must(template.New("metadata").Parse(tmpl))
	var metadata bytes.Buffer
	t.Execute(&metadata, aux)

	return metadata.String()
}
