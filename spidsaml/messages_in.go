package spidsaml

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/russellhaering/goxmldsig/etreeutils"
)

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

func (msg *inMessage) read(r *http.Request, param string) error {
	var xml []byte
	var err error

	switch r.Method {
	case "POST":
		r.ParseForm()
		xml, err = _readPost(r, param)
	case "GET":
		xml, err = _readGet(r, param)
	default:
		err = fmt.Errorf("invalid HTTP method: %s", r.Method)
	}

	if err != nil {
		return err
	}

	msg.RelayState = r.FormValue("RelayState")

	return msg.SetXML(xml)
}

func _readGet(r *http.Request, param string) ([]byte, error) {
	samlEncoding := r.URL.Query().Get("SAMLEncoding")
	if samlEncoding != "" && samlEncoding != "urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE" {
		return nil, errors.New("invalid SAMLEncoding")
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

func _readPost(r *http.Request, param string) ([]byte, error) {
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
		return msg.validateSignatureForPost(msg.doc.Root())

	case "GET":
		return msg.validateSignatureForGet(param, r.URL.Query())

	default:
		return fmt.Errorf("invalid HTTP method: %s", r.Method)
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
		return fmt.Errorf("unknown SigAlg: %s", query.Get("SigAlg"))
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

func (msg *inMessage) validateSignatureForPost(el *etree.Element) error {
	// Check presence of signature
	sigEl := msg.doc.FindElement("//Signature[namespace-uri()='http://www.w3.org/2000/09/xmldsig#']")
	if sigEl == nil {
		return errors.New("signature element not found")
	}

	// Initialize validation
	certificateStore := dsig.MemoryX509CertificateStore{
		Roots: msg.IDP.Certs,
	}
	validationContext := dsig.NewDefaultValidationContext(&certificateStore)
	validationContext.IdAttribute = "ID"
	if msg.clock != nil {
		validationContext.Clock = msg.clock
	}

	ctx, err := etreeutils.NSBuildParentContext(el)
	if err != nil {
		return fmt.Errorf("cannot validate signature on %s: %v", el.Tag, err)
	}
	ctx, err = ctx.SubContext(el)
	if err != nil {
		return fmt.Errorf("cannot validate signature on %s: %v", el.Tag, err)
	}
	el, err = etreeutils.NSDetatch(ctx, el)
	if err != nil {
		return fmt.Errorf("cannot validate signature on %s: %v", el.Tag, err)
	}

	if _, err := validationContext.Validate(el); err != nil {
		return fmt.Errorf("cannot validate signature on %s: %v", el.Tag, err)
	}

	return nil
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
