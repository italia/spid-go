package spidsaml

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"text/template"
	"time"

	"github.com/beevik/etree"
	xmlsec "github.com/crewjam/go-xmlsec"
)

// protocolMessage is the base class for all SAML messages
type protocolMessage struct {
	SP  *SP
	IDP *IDP
}

// outMessage is the base class for all outgoing message
type outMessage struct {
	protocolMessage
	ID           string
	issueInstant *time.Time
	RelayState   string
}

type inMessage struct {
	protocolMessage
	XML []byte
	doc *etree.Document
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
		t := time.Now().UTC()
		msg.issueInstant = &t
	}
	return msg.issueInstant
}

func (msg *outMessage) IssueInstantString() string {
	return msg.IssueInstant().Format("2006-01-02T15:04:05.000Z")
}

// RedirectURL crafts the URL to be used for sending the current message via a HTTPRedirect binding
func (msg *outMessage) RedirectURL(baseurl string, xml []byte, param string) string {
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
	query := ret.Query()
	query.Set(param, string(w.Bytes()))
	if msg.RelayState != "" {
		query.Set("RelayState", msg.RelayState)
	}
	query.Set("SigAlg", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")

	// sign request
	h := sha256.New()
	h.Write([]byte(query.Encode()))
	d := h.Sum(nil)
	signature, err := rsa.SignPKCS1v15(rand.Reader, msg.SP.Key(), crypto.SHA256, d)
	if err != nil {
		panic(err)
	}
	query.Set("Signature", base64.StdEncoding.EncodeToString(signature))

	ret.RawQuery = query.Encode()
	return ret.String()
}

// PostForm returns an HTML page with a JavaScript auto-post command that submits
// the request to the Identity Provider in order to initiate their Single Sign-On.
// In SAML words, this implements the HTTP-POST binding.
func (msg *outMessage) PostForm(url string, xml []byte, param string) []byte {
	// We need to get the name of the root element
	doc := etree.NewDocument()
	doc.ReadFromBytes(xml)

	signedDoc, err := xmlsec.Sign(msg.SP.KeyPEM(), xml, xmlsec.SignatureOptions{
		XMLID: []xmlsec.XMLIDOption{
			{
				ElementName:      doc.Root().Tag,
				ElementNamespace: "",
				AttributeName:    "ID",
			},
		},
	})
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

func (msg *outMessage) signatureTemplate() []byte {
	tmpl := template.Must(template.New("saml-post-form").Parse(`
 <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" />
      <ds:Reference URI="#{{ .Ref }}">
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
	`))
	data := struct {
		Ref  string
		Cert string
	}{
		msg.ID,
		base64.StdEncoding.EncodeToString(msg.SP.Cert().Raw),
	}

	var rv bytes.Buffer
	tmpl.Execute(&rv, data)
	return rv.Bytes()
}

func (msg *inMessage) parseB64(payload string) error {
	var err error
	msg.XML, err = base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return err
	}

	err = msg.initDoc()
	if err != nil {
		return err
	}

	return nil
}

func (msg *inMessage) validate() error {
	var err error
	msg.IDP, err = msg.SP.GetIDP(msg.Issuer())
	if err != nil {
		return err
	}
	return nil
}

func (msg *inMessage) initDoc() error {
	msg.doc = etree.NewDocument()
	return msg.doc.ReadFromBytes(msg.XML)
}

// Issuer returns the value of the <Issuer> element.
func (msg *inMessage) Issuer() string {
	return msg.doc.FindElement("/*/Issuer").Text()
}

// InResponseTo returns the value of the <InResponseTo> element.
func (msg *inMessage) InResponseTo() string {
	return msg.doc.Root().SelectAttrValue("InResponseTo", "")
}

// Destination returns the value of the <Destination> element.
func (msg *inMessage) Destination() string {
	return msg.doc.Root().SelectAttrValue("Destination", "")
}
