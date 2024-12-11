package spidsaml

import (
	"bytes"
	"text/template"
)

// LogoutResponseOut defines an outgoing SPID/SAML LogoutResponse.
// You need to craft such a response in case you received a LogoutRequest
// from the Identity Provider, thus during an IdP-initiated logout.
// Do not instantiate it directly but use sp.NewLogoutResponse() instead.
type LogoutResponseOut struct {
	outMessage
	InResponseTo string
}

// LogoutStatus represent the possible result statuses of Single Logout.
type LogoutStatus string

// LogoutStatus represent the possible result statuses of Single Logout.
const (
	SuccessLogout LogoutStatus = "success"
	PartialLogout LogoutStatus = "partial"
)

// NewLogoutResponse generates a LogoutRequest addressed to the Identity Provider.
// Note that this method does not perform any network call, it just initializes
// an object.
func (sp *SP) NewLogoutResponse(logoutreq *LogoutRequestIn, status LogoutStatus) (*LogoutResponseOut, error) {
	res := new(LogoutResponseOut)
	res.SP = sp
	res.IDP = logoutreq.IDP
	res.ID = generateMessageID()
	res.InResponseTo = logoutreq.ID()
	return res, nil
}

// XML generates the XML representation of this LogoutResponseOut
func (logoutres *LogoutResponseOut) XML(binding SAMLBinding) []byte {
	data := struct {
		*LogoutResponseOut
		Destination  string
		IssueInstant string
	}{
		logoutres,
		//logoutres.IDP.SLOResURLs[binding],  // This would be the SAML standard
		logoutres.IDP.EntityID, // This is the SPID spec
		logoutres.IssueInstantString(),
	}

	// TODO: what should we send in case of .Status == "failed"?
	// TODO: is it correct to send PartialLogout in case of .Status == "partial"?

	const tmpl = `<?xml version="1.0"?> 
	<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
		xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
		ID="{{ .ID }}"
		Version="2.0"
		IssueInstant="{{ .IssueInstant }}"
		Destination="{{ .Destination }}"
		InResponseTo="{{ .InResponseTo }}">
	
	<saml:Issuer
		NameQualifier="{{ .SP.EntityID }}"
		Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">
		{{ .SP.EntityID }}
	</saml:Issuer>

	<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" />

	<samlp:Status>
		{{ if eq .Status "success" }}
			<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
		{{ else if eq .Status "partial" }}
			<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester">
				<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:PartialLogout" />
			</samlp:StatusCode>
		{{ end }}
	</samlp:Status>
</samlp:LogoutRequest>
`

	t := template.Must(template.New("req").Parse(tmpl))
	var metadata bytes.Buffer
	t.Execute(&metadata, data)
	return metadata.Bytes()
}

// RedirectURL returns the full URL of the Identity Provider where user should be
// redirected in order to continue their Single Logout. In SAML words, this
// implements the HTTP-Redirect binding.
func (logoutres *LogoutResponseOut) RedirectURL() string {
	return logoutres.outMessage.RedirectURL(
		logoutres.IDP.SLOResURLs[HTTPRedirect],
		logoutres.XML(HTTPRedirect),
		"SAMLResponse",
	)
}

// PostForm returns an HTML page with a JavaScript auto-post command that submits
// the request to the Identity Provider in order to complete their Single Logout.
// In SAML words, this implements the HTTP-POST binding.
func (logoutres *LogoutResponseOut) PostForm() []byte {
	return logoutres.outMessage.PostForm(
		logoutres.IDP.SLOResURLs[HTTPPost],
		logoutres.XML(HTTPPost),
		"SAMLResponse",
	)
}
