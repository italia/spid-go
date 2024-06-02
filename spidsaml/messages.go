package spidsaml

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"text/template"
	"time"

	"github.com/beevik/etree"
	xmlsec "github.com/crewjam/go-xmlsec"
	dsig "github.com/russellhaering/goxmldsig"
)

// protocolMessage is the base class for all SAML messages
type protocolMessage struct {
	SP    *SP
	IDP   *IDP
	clock *Clock
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
	XML        []byte
	doc        *etree.Document
	RelayState string
}

func (msg *inMessage) SetXML(xml []byte) error {
	msg.XML = xml
	msg.doc = etree.NewDocument()
	return msg.doc.ReadFromBytes(xml)
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

func getSigningContext(sp *SP) *dsig.SigningContext {
	// Prepare key and certificate
	keyPair, err := tls.X509KeyPair(sp.CertPEM(), sp.KeyPEM())
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
	signingContext := getSigningContext(msg.SP)
	sig, err := signingContext.SignString(query)
	if err != nil {
		panic(err)
	}

	query += "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig))

	ret.RawQuery = query
	return ret.String()
}

func SignXML(xml []byte, sp *SP) ([]byte, error) {
	signingContext := getSigningContext(sp)

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

func (msg *inMessage) parse(r *http.Request, param string) error {
	var xml []byte
	var err error

	switch r.Method {
	case "POST":
		xml, err = parsePost(r, param)
	case "GET":
		xml, err = parseGet(r, param)
	default:
		err = fmt.Errorf("Invalid HTTP method: %s", r.Method)
	}

	if err != nil {
		return err
	}

	msg.RelayState = r.URL.Query().Get("RelayState")

	return msg.SetXML(xml)
}

func parseGet(r *http.Request, param string) ([]byte, error) {
	samlEncoding := r.URL.Query().Get("SAMLEncoding")
	if samlEncoding != "" && samlEncoding != "urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE" {
		return nil, errors.New("Invalid SAMLEncoding")
	}

	payload, err := base64.StdEncoding.DecodeString(r.URL.Query().Get(param))
	if err != nil {
		return nil, err
	}

	b := bytes.NewReader(payload)
	r2 := flate.NewReader(b)
	defer r2.Close()
	return ioutil.ReadAll(r2)
}

func parsePost(r *http.Request, param string) ([]byte, error) {
	r.ParseForm()
	return base64.StdEncoding.DecodeString(r.Form.Get(param))
}

func (msg *inMessage) matchIncomingIDP() error {
	var err error
	msg.IDP, err = msg.SP.GetIDP(strings.TrimSpace(msg.Issuer()))
	if err != nil {
		return err
	}

	// TODO: validate IssueInstant

	return nil
}

func (msg *inMessage) validateSignature(r *http.Request, param string) error {
	switch r.Method {
	case "POST":
		return msg.validateSignatureForPost()

	case "GET":
		query := r.URL.Query()
		return msg.validateSignatureForGet(param, query)

	default:
		return fmt.Errorf("Invalid HTTP method: %s", r.Method)
	}
}

func (msg *inMessage) validateSignatureForGet(param string, query url.Values) error {
	// In order to verify the signature we need to concatenate arguments
	// according to a predefined order (the request URI might be ordered
	// in a different way)
	var params []string
	for _, key := range []string{param, "RelayState", "SigAlg"} {
		if _, exists := query[key]; exists {
			params = append(params, fmt.Sprintf("%s=%s",
				key, url.QueryEscape(query.Get(key))))
		}
	}

	// Encode the payload
	payload := []byte(strings.Join(params, "&"))

	// Decode the signature from Base64
	sig, err := base64.StdEncoding.DecodeString(query.Get("Signature"))
	if err != nil {
		return err
	}

	// Compute the hash of the payload according to the declared SigAlg
	var h []byte
	var hashAlg crypto.Hash
	if query.Get("SigAlg") == "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" {
		h2 := sha256.Sum256(payload)
		h = h2[:]
		hashAlg = crypto.SHA256
	} else if query.Get("SigAlg") == "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384" {
		h2 := sha512.Sum384(payload)
		h = h2[:]
		hashAlg = crypto.SHA384
	} else if query.Get("SigAlg") == "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512" {
		h2 := sha512.Sum512(payload)
		h = h2[:]
		hashAlg = crypto.SHA512
	} else {
		return fmt.Errorf("Unknown SigAlg: %s", query.Get("SigAlg"))
	}

	// Verify the signature
	for _, cert := range msg.IDP.Certs {
		err = rsa.VerifyPKCS1v15(cert.PublicKey.(*rsa.PublicKey), hashAlg, h, sig)
		if err == nil {
			return nil
		}
	}

	return err
}

func (msg *inMessage) validateSignatureForPost() error {
	var err error
	for _, cert := range msg.IDP.CertPEM() {
		err = xmlsec.Verify(cert, msg.XML, xmlsec.SignatureOptions{
			XMLID: []xmlsec.XMLIDOption{
				{
					ElementName:      msg.doc.Root().Tag,
					ElementNamespace: "",
					AttributeName:    "ID",
				},
			},
		})
		if err == nil {
			return nil
		}
	}
	return fmt.Errorf("%s signature verification failed: %s",
		msg.doc.Root().Tag, err.Error())
}

// ID returns the message ID.
func (msg *inMessage) ID() string {
	return msg.doc.Root().SelectAttrValue("ID", "")
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
