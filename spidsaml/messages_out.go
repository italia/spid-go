package spidsaml

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"text/template"
	"time"

	"github.com/beevik/etree"
)

// outMessage is the base class for all outgoing message
type outMessage struct {
	protocolMessage
	ID           string
	issueInstant *time.Time
	RelayState   string
}

func generateMessageID() string {
	id := make([]byte, 16)
	if _, err := rand.Reader.Read(id); err != nil {
		panic(err)
	}

	// first character must not be a digit
	return fmt.Sprintf("_%x", id)
}

func (msg *outMessage) IssueInstant() *time.Time {
	if msg.issueInstant == nil {
		t := msg.clock.Now().UTC()
		msg.issueInstant = &t
	}
	return msg.issueInstant
}

func (msg *outMessage) IssueInstantString() string {
	return msg.IssueInstant().Format("2006-01-02T15:04:05.000Z")
}

// RedirectURL crafts the URL to be used for sending the current message via a HTTPRedirect binding
func (msg *outMessage) RedirectURL(baseurl string, xml []byte, param string) string {
	// Remove signature placeholder
	doc := etree.NewDocument()
	doc.ReadFromBytes(xml)
	sigPlaceholderEl := doc.FindElement("//ds:Signature")
	if sigPlaceholderEl != nil {
		sigPlaceholderEl.Parent().RemoveChild(sigPlaceholderEl)
	}
	xml, err := doc.WriteToBytes()
	if err != nil {
		panic(err)
	}

	// Compress and encode XML document
	w := &bytes.Buffer{}
	w1 := base64.NewEncoder(base64.StdEncoding, w)
	w2, _ := flate.NewWriter(w1, 9)
	w2.Write([]byte(xml))
	w2.Close()
	w1.Close()

	ret, err := url.Parse(baseurl)
	if err != nil {
		panic(err)
	}
	// We can't depend on Query().set() as order matters for signing
	query := ret.RawQuery
	if len(query) > 0 {
		query += "&"
	}
	query += param + "=" + url.QueryEscape(w.String())
	query += "&RelayState=" + url.QueryEscape(msg.RelayState)
	query += "&SigAlg=" + url.QueryEscape("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")

	// sign request
	signingContext := msg.SP.GetSigningContext()
	sig, err := signingContext.SignString(query)
	if err != nil {
		panic(err)
	}

	query += "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig))

	ret.RawQuery = query
	return ret.String()
}

func SignXML(xml []byte, sp *SP) ([]byte, error) {
	signingContext := sp.GetSigningContext()

	// Get the position of the signature element and remove it so that it does not
	// affect the digest
	doc := etree.NewDocument()
	doc.ReadFromBytes(xml)
	sigPlaceholderEl := doc.FindElement("//ds:Signature")
	if sigPlaceholderEl == nil {
		return nil, errors.New("signature element not found")
	}
	sigParent := sigPlaceholderEl.Parent()
	sigIndex := sigPlaceholderEl.Index()
	sigParent.RemoveChildAt(sigIndex)

	// Perform the signature
	signedDocEl, err := signingContext.SignEnveloped(doc.Root())
	if err != nil {
		return nil, err
	}

	// Signature element was placed at the end; extract it and place it in the
	// desired position
	sigEl := signedDocEl.Child[len(signedDocEl.Child)-1]
	sigParent.InsertChildAt(sigIndex, sigEl)

	return doc.WriteToBytes()
}

// PostForm returns an HTML page with a JavaScript auto-post command that submits
// the request to the Identity Provider in order to initiate their Single Sign-On.
// In SAML words, this implements the HTTP-POST binding.
func (msg *outMessage) PostForm(url string, xml []byte, param string) []byte {
	signedDoc, err := SignXML(xml, msg.SP)
	if err != nil {
		panic(err)
	}
	//os.Stdout.Write(signedDoc)

	// encode in base64
	encodedReqBuf := base64.StdEncoding.EncodeToString(signedDoc)

	tmpl := template.Must(template.New("saml-post-form").Parse(`
<html>
    <body onload="javascript:document.forms[0].submit()">
        <form method="post" action="{{ .URL }}">
            <input type="hidden" name="{{ .Param }}" value="{{ .Payload }}">
            <input type="hidden" name="RelayState" value="{{ .RelayState }}">
        </form>
    </body>
</html>
`))
	data := struct {
		URL        string
		Param      string
		Payload    string
		RelayState string
	}{
		url,
		param,
		encodedReqBuf,
		msg.RelayState,
	}

	rv := bytes.Buffer{}
	if err := tmpl.Execute(&rv, data); err != nil {
		panic(err)
	}

	return rv.Bytes()
}
