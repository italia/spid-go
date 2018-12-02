package spid

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
	"time"
)

// protocolMessage is the base class for all SAML messages
type protocolMessage struct {
	SP *SP
}

// Message is the base class for all outgoing message
type outMessage struct {
	protocolMessage
	IDP          *IDP
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
		t := time.Now().UTC()
		msg.issueInstant = &t
	}
	return msg.issueInstant
}

func (msg *outMessage) IssueInstantString() string {
	return msg.IssueInstant().Format("2006-01-02T15:04:05.000Z")
}

// RedirectURL crafts the URL to be used for sending the current message via a HTTPRedirect binding
func (msg *outMessage) RedirectURL(baseurl string, xml string, param string) string {
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
