package spid

import (
	"bytes"
	"text/template"
)

// OutAuthnRequest defines an outgoing SPID/SAML AuthnRequest.
// Do not instantiate it directly but use idp.NewAuthnRequest() instead.
type OutAuthnRequest struct {
	outMessage
	AcsURL     string
	AcsIndex   int
	AttrIndex  int
	Level      int
	Comparison string
}

// NewAuthnRequest generates an AuthnRequest addressed to this Identity Provider.
// Note that this method does not perform any network call, it just initializes
// an object.
func NewAuthnRequest(sp *SP, idp *IDP) *OutAuthnRequest {
	req := new(OutAuthnRequest)
	req.SP = sp
	req.IDP = idp
	req.ID = generateMessageID()
	req.AcsIndex = -1
	req.AttrIndex = -1
	req.Level = 1
	req.Comparison = "minimum"
	return req
}

// XML generates the XML representation of this AuthnRequest
func (authnreq *OutAuthnRequest) XML(binding SAMLBinding) string {
	data := struct {
		*OutAuthnRequest
		IssueInstant string
		Destination  string
		EntityID     string
	}{
		authnreq,
		authnreq.IssueInstantString(),
		authnreq.IDP.EntityID,
		authnreq.SP.EntityID,
	}

	// According to SAML rules, Destination should be set to self.GetIdPSSOURL(binding)
	// but SPID rules want the entityID instead.

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
	
	<saml:Issuer
        NameQualifier="{{ .EntityID }}"
        Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">
        {{ .EntityID }}
	</saml:Issuer>

    <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient" />
    <samlp:RequestedAuthnContext Comparison="{{ .Comparison }}">
        <saml:AuthnContextClassRef>
            https://www.spid.gov.it/SpidL{{ .Level }}
        </saml:AuthnContextClassRef>
    </samlp:RequestedAuthnContext>
</samlp:AuthnRequest>
`
	// TODO: add signature between Issuer and NameIDPolicy if binding is POST

	t := template.Must(template.New("metadata").Parse(tmpl))
	var metadata bytes.Buffer
	t.Execute(&metadata, data)

	return metadata.String()
}

// RedirectURL returns the full URL of the Identity Provider where user should be
// redirected in order to initiate their Single Sign-On. In SAML words, this
// implements the HTTP-Redirect binding.
func (authnreq *OutAuthnRequest) RedirectURL() string {
	return authnreq.outMessage.RedirectURL(
		authnreq.IDP.SSOURLs[HTTPRedirect],
		authnreq.XML(HTTPRedirect),
		"SAMLRequest",
	)
}
