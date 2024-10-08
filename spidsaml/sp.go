package spidsaml

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
	"text/template"

	dsig "github.com/russellhaering/goxmldsig"
)

// AttributeConsumingService defines, well, an AttributeConsumingService.
type AttributeConsumingService struct {
	ServiceName string
	Attributes  []string
}

// Organization defines SP Organization data
type Organization struct {
	Names        []string
	DisplayNames []string
	URLs         []string
}

type ContactPerson struct {
	Email   string
	IPACode string
}

// SAMLBinding can be either HTTPRedirect or HTTPPost.
type SAMLBinding string

// Constants for SAMLBinding
const (
	HTTPRedirect SAMLBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	HTTPPost     SAMLBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
)

// SP represents our Service Provider
type SP struct {
	EntityID                   string
	Key                        []byte
	KeyFile                    string
	Cert                       []byte
	CertFile                   string
	AssertionConsumerServices  []string
	SingleLogoutServices       map[string]SAMLBinding
	AttributeConsumingServices []AttributeConsumingService
	IDP                        map[string]*IDP
	_cert                      *x509.Certificate
	_key                       *rsa.PrivateKey
	Organization               Organization
	ContactPerson              ContactPerson
}

// CertPEM returns the certificate of this Service Provider in PEM format.
func (sp *SP) GetCertPEM() []byte {
	var block = &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: sp.GetCert().Raw,
	}
	return pem.EncodeToMemory(block)
}

// Cert returns the certificate of this Service Provider.
func (sp *SP) GetCert() *x509.Certificate {
	if sp._cert == nil {
		if len(sp.Cert) == 0 {
			// read file as a byte array
			var err error
			sp.Cert, err = os.ReadFile(sp.CertFile)
			if err != nil {
				panic(err)
			}
		}

		block, _ := pem.Decode(sp.Cert)
		if block == nil || block.Type != "CERTIFICATE" {
			panic("failed to parse certificate PEM")
		}
		sp.Cert = []byte{}

		var err error
		sp._cert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			panic(err)
		}
	}
	return sp._cert
}

// Key returns the private key of this Service Provider
func (sp *SP) GetKey() *rsa.PrivateKey {
	if sp._key == nil {
		if len(sp.Key) == 0 {
			// read file as a byte array
			var err error
			sp.Key, err = os.ReadFile(sp.KeyFile)
			if err != nil {
				panic(err)
			}
		}

		block, _ := pem.Decode(sp.Key)
		if block == nil {
			panic("failed to parse private key from PEM file " + sp.KeyFile)
		}
		sp.Key = []byte{}

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
func (sp *SP) GetKeyPEM() []byte {
	key := sp.GetKey()
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
    xmlns:spid="https://spid.gov.it/saml-extensions"
    xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"  
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#"  
    entityID="{{.EntityID}}"  
    ID="{{.ID}}">

	<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" />
     
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
        {{ range $name := .Organization.Names }}
        <md:OrganizationName xml:lang="it">{{ $name }}</md:OrganizationName>
        {{ end }}
        {{ range $displayName := .Organization.DisplayNames }}
        <md:OrganizationDisplayName xml:lang="it">{{ $displayName }}</md:OrganizationDisplayName>
        {{ end }}
        {{ range $url := .Organization.URLs }}
        <md:OrganizationURL xml:lang="it">{{ $url }}</md:OrganizationURL>
        {{ end }}
    </md:Organization>

    <md:ContactPerson contactType="other">
        <md:Extensions>
            <spid:IPACode>{{.ContactPerson.IPACode}}</spid:IPACode>
            <spid:Public/>
        </md:Extensions>
        <md:EmailAddress>{{.ContactPerson.Email}}</md:EmailAddress>
    </md:ContactPerson>

</md:EntityDescriptor>
`

	var ID = "_681a637-6cd4-434f-92c3-4fed720b2ad8"
	aux := struct {
		ID string
		*SP
		Cert string
	}{
		ID,
		sp,
		base64.StdEncoding.EncodeToString(sp.GetCert().Raw),
	}

	t := template.Must(template.New("metadata").Parse(tmpl))
	var metadata bytes.Buffer
	t.Execute(&metadata, aux)

	signedDoc, err := SignXML(metadata.Bytes(), sp)
	if err != nil {
		os.Stderr.WriteString("Metadata signature failed: " + err.Error() + "\n")
		signedDoc = metadata.Bytes()
	}

	return string(signedDoc)
}

func (sp *SP) GetSigningContext() *dsig.SigningContext {
	// Prepare key and certificate
	keyPair, err := tls.X509KeyPair(sp.GetCertPEM(), sp.GetKeyPEM())
	if err != nil {
		panic(err)
	}
	keyStore := dsig.TLSCertKeyStore(keyPair)

	ctx := dsig.NewDefaultSigningContext(keyStore)
	ctx.IdAttribute = "ID"
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	ctx.SetSignatureMethod(dsig.RSASHA256SignatureMethod)
	return ctx
}
