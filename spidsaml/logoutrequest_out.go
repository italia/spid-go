package spidsaml

import (
	"bytes"
	"text/template"
)

// LogoutRequestOut defines an outgoing SPID/SAML LogoutRequest.
// You can use it to generate such a request in case you're initiating
// a logout procedure on behalf of your user.
// Do not instantiate it directly but use sp.NewLogoutRequest() instead.
type LogoutRequestOut struct {
	outMessage
	Session *Session
}

// NewLogoutRequest generates a LogoutRequest addressed to the Identity Provider.
// Note that this method does not perform any network call, it just initializes
// an object.
func (sp *SP) NewLogoutRequest(session *Session) (*LogoutRequestOut, error) {
	req := new(LogoutRequestOut)
	req.SP = sp
	var err error
	req.IDP, err = sp.GetIDP(session.IDPEntityID)
	if err != nil {
		return nil, err
	}
	req.ID = generateMessageID()
	req.Session = session
	return req, nil
}

// XML generates the XML representation of this LogoutRequest
func (logoutreq *LogoutRequestOut) XML(binding SAMLBinding) []byte {
	data := struct {
		*LogoutRequestOut
		Destination  string
		IssueInstant string
	}{
		logoutreq,
		//logoutreq.IDP.SLOReqURLs[binding],   // This would be the SAML standard
		logoutreq.SP.EntityID, // This is the SPID spec
		logoutreq.IssueInstantString(),
	}

	const tmpl = `<?xml version="1.0"?> 
	<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
		xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
		ID="{{ .ID }}"
		Version="2.0"
		IssueInstant="{{ .IssueInstant }}"
		Destination="{{ .Destination }}">
	
	<saml:Issuer
		NameQualifier="{{ .SP.EntityID }}"
		Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">
		{{ .SP.EntityID }}
	</saml:Issuer>

	<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" />

	<saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient" 
		NameQualifier="{{ .Session.IDPEntityID }}">
		{{ .Session.NameID }}
	</saml:NameID>

	<samlp:SessionIndex>
		{{ .Session.SessionIndex }}
	</samlp:SessionIndex>
</samlp:LogoutRequest>
`

	t := template.Must(template.New("req").Parse(tmpl))
	var metadata bytes.Buffer
	t.Execute(&metadata, data)
	return metadata.Bytes()
}

// RedirectURL returns the full URL of the Identity Provider where user should be
// redirected in order to initiate their Single Logout. In SAML words, this
// implements the HTTP-Redirect binding.
func (logoutreq *LogoutRequestOut) RedirectURL() string {
	return logoutreq.outMessage.RedirectURL(
		logoutreq.IDP.SLOReqURLs[HTTPRedirect],
		logoutreq.XML(HTTPRedirect),
		"SAMLRequest",
	)
}

// PostForm returns an HTML page with a JavaScript auto-post command that submits
// the request to the Identity Provider in order to initiate their Single Logout.
// In SAML words, this implements the HTTP-POST binding.
func (logoutreq *LogoutRequestOut) PostForm() []byte {
	return logoutreq.outMessage.PostForm(
		logoutreq.IDP.SLOReqURLs[HTTPPost],
		logoutreq.XML(HTTPPost),
		"SAMLRequest",
	)
}
