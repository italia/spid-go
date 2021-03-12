package spidsaml

import (
	"crypto/rsa"
	"crypto/x509"
	"strings"
	"testing"
)

func TestSP_Key(t *testing.T) {
	cases := []struct {
		keyFile   string
		returnErr bool
		name      string
	}{
		{
			keyFile:   "non_existing_file.pem",
			returnErr: true,
			name:      "Gives error when key file does not exist",
		},
		{
			keyFile:   "../fixtures/key.rsa.pem",
			returnErr: false,
			name:      "Can read a key in PKS1 format",
		},
		{
			keyFile:   "../fixtures/key.pem",
			returnErr: false,
			name:      "Can read a key in PKS8 format",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := readKey(tc.keyFile)
			returnedErr := err != nil

			if returnedErr != tc.returnErr {
				t.Fail()
			}
		})
	}
}

func TestSP_Cert(t *testing.T) {
	cases := []struct {
		certFile  string
		returnErr bool
		name      string
	}{
		{
			certFile:  "non_existing_file.pem",
			returnErr: true,
			name:      "Gives error when certificate file does not exist",
		},
		{
			certFile:  "../fixtures/crt.pem",
			returnErr: false,
			name:      "Can read a certificate file",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := readCert(tc.certFile)
			returnedErr := err != nil

			if returnedErr != tc.returnErr {
				t.Fail()
			}
		})
	}
}

func TestSP_Metadata(t *testing.T) {
	sp := &SP{
		EntityID: "https://spid.comune.roma.it",
		KeyFile:  "../fixtures/key.pem",
		CertFile: "../fixtures/crt.pem",
		AssertionConsumerServices: []string{
			"http://localhost:8000/spid-sso",
		},
		SingleLogoutServices: map[string]SAMLBinding{
			"http://localhost:8000/spid-slo": HTTPRedirect,
		},
		AttributeConsumingServices: []AttributeConsumingService{
			{
				ServiceName: "Service 1",
				Attributes:  []string{"fiscalNumber", "name", "familyName", "dateOfBirth"},
			},
		},
	}
	cases := []struct {
		attribute   string
		name      string
	}{
		{
			attribute: `entityID="https://spid.comune.roma.it"`,
			name:		"Contains the right entityID",
		},
	}
	metadata := sp.Metadata()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(metadata, tc.attribute)  {
				t.Fail()
			}
		})
	}
}

func readCert(certFile string) (key *x509.Certificate, err interface{}) {
	defer func() {
		err = recover()
	}()
	sp := &SP {
		CertFile: certFile,
	}
	return sp.Cert(), nil
}

func readKey(keyFile string) (key *rsa.PrivateKey, err interface{}) {
	defer func() {
		err = recover()
	}()
	sp := &SP {
		KeyFile: keyFile,
	}
	return sp.Key(), nil
}