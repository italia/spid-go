package spidsaml

import (
	"bytes"
	"strconv"
	"text/template"
)

// AuthnRequest defines an outgoing SPID/SAML AuthnRequest.
// Do not instantiate it directly but use sp.NewAuthnRequest() instead.
type AuthnRequest struct {
	outMessage
	AcsURL     string
	AcsIndex   int
	AttrIndex  int
	Level      int
	Comparison string
	UseMyID    bool
}

// NewAuthnRequest generates an AuthnRequest addressed to this Identity Provider.
// Note that this method does not perform any network call, it just initializes
// an object.
func (sp *SP) NewAuthnRequest(idp *IDP) *AuthnRequest {
	req := new(AuthnRequest)
	req.SP = sp
	req.IDP = idp
	req.ID = GenerateRandomID()
	req.AcsIndex = -1
	req.AttrIndex = -1
	req.Level = 1
	req.Comparison = "minimum"
	return req
}

// XML generates the XML representation of this AuthnRequest
// Applicato il bugfix di saml:Issuer
func (authnreq *AuthnRequest) XML(binding SAMLBinding) []byte {
	var signatureTemplate string
	if binding == HTTPPost {
		signatureTemplate = string(authnreq.signatureTemplate())
	}

	data := struct {
		*AuthnRequest
		Destination       string
		IssueInstant      string
		SignatureTemplate string
	}{
		authnreq,
		authnreq.IDP.SSOURLs[binding],
		authnreq.IssueInstantString(),
		signatureTemplate,
	}

	const tmpl = `<?xml version="1.0"?> 
	<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{{ .ID }}"
    Version="2.0"
    IssueInstant="{{ .IssueInstant }}"
	Destination="{{ .Destination }}"
	
	{{ if ne .AcsURL "" }}
    AssertionConsumerServiceURL="{{ .AcsURL }}"
	ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
	{{ else if ne .AcsIndex -1 }}
	AssertionConsumerServiceIndex="{{ .AcsIndex }}"
	{{ end }}
	
	{{ if ne .AttrIndex -1 }}
	AttributeConsumingServiceIndex="{{ .AttrIndex }}"
	{{ end }}

	ForceAuthn="{{ if gt .Level 1 }}true{{ else }}false{{ end }}">
	
	<saml:Issuer NameQualifier="{{ .SP.EntityID }}" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">{{ .SP.EntityID }}</saml:Issuer>

	{{ .SignatureTemplate }}

    <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient" />
    <samlp:RequestedAuthnContext Comparison="{{ .Comparison }}">
        <saml:AuthnContextClassRef>https://www.spid.gov.it/SpidL{{ .Level }}</saml:AuthnContextClassRef>
    </samlp:RequestedAuthnContext>
</samlp:AuthnRequest>
`

	t := template.Must(template.New("req").Parse(tmpl))
	var metadata bytes.Buffer

	if t.Execute(&metadata, data) != nil {
		return nil
	}

	return metadata.Bytes()
}

// XMLMyID generates the XML representation of this AuthnRequest using
// MyID-compatible AuthnContextClassRef values based on Level.
func (authnreq *AuthnRequest) XMLMyID(binding SAMLBinding) []byte {
	xml := authnreq.XML(binding)
	if xml == nil {
		return nil
	}

	var authnContextClassRef string
	switch authnreq.Level {
	case 1:
		authnContextClassRef = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
	case 2:
		authnContextClassRef = "urn:oasis:names:tc:SAML:2.0:ac:classes:SecureRemotePassword"
	case 3:
		authnContextClassRef = "urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard"
	default:
		return xml
	}

	spidClassRef := "https://www.spid.gov.it/SpidL" + strconv.Itoa(authnreq.Level)
	return bytes.Replace(xml, []byte(spidClassRef), []byte(authnContextClassRef), 1)
}

func (authnreq *AuthnRequest) xmlForBinding(binding SAMLBinding) []byte {
	if authnreq.UseMyID {
		return authnreq.XMLMyID(binding)
	}
	return authnreq.XML(binding)
}

// RedirectURL returns the full URL of the Identity Provider where user should be
// redirected in order to initiate their Single Sign-On. In SAML words, this
// implements the HTTP-Redirect binding.
func (authnreq *AuthnRequest) RedirectURL() string {
	return authnreq.outMessage.RedirectURL(
		authnreq.IDP.SSOURLs[HTTPRedirect],
		authnreq.xmlForBinding(HTTPRedirect),
		"SAMLRequest",
	)
}

// PostForm returns an HTML page with a JavaScript auto-post command that submits
// the request to the Identity Provider in order to initiate their Single Sign-On.
// In SAML words, this implements the HTTP-POST binding.
func (authnreq *AuthnRequest) PostForm() []byte {
	return authnreq.outMessage.PostForm(
		authnreq.IDP.SSOURLs[HTTPPost],
		authnreq.xmlForBinding(HTTPPost),
		"SAMLRequest",
	)
}
