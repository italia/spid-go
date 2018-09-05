package spid

import (
    "crypto/x509"
    "encoding/base64"
    "encoding/pem"
    "io/ioutil"
    "github.com/crewjam/saml"
    "os"
)

type AttributeConsumingService struct {
    ServiceName                 string
    Attributes                  []string
}

type SAMLBinding string
const (
    HTTPRedirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
    HTTPPost     = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
)

// this class represents our Service Provider
type SP struct {
    EntityID                    string
    KeyFile                     string
    CertFile                    string
    AssertionConsumerServices   []string
    SingleLogoutServices        map[string]SAMLBinding
    AttributeConsumingServices  []AttributeConsumingService
    IdP                         map[string]*saml.EntityDescriptor
    Cert                        string
    Key                         string
}

// idempotent method to make sure .Cert is populated
func (sp *SP) LoadCert() {
    if (sp.Cert == "") {
        certFile, err := os.Open(sp.CertFile)
        if err != nil {
            panic(err)
        }
        defer certFile.Close()
    
        // read our opened certFile as a byte array
        byteValue, _ := ioutil.ReadAll(certFile)
        
        block, _ := pem.Decode(byteValue)
        if block == nil || block.Type != "CERTIFICATE" {
            panic("failed to parse certificate PEM")
        }
        
        cert, err := x509.ParseCertificate(block.Bytes)
        if err != nil {
            panic(err)
        }
        sp.Cert = base64.StdEncoding.EncodeToString(cert.Raw)
    }
}
