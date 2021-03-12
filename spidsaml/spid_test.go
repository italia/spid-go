package spidsaml

import (
	"crypto/rsa"
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

func readKey(keyFile string) (key *rsa.PrivateKey, err interface{}) {
	defer func() {
		err = recover()
	}()
	sp := createSPWith(keyFile)
	return sp.Key(), nil
}

func createSPWith(keyFile string) *SP {
	sp := &SP{
		EntityID: "https://spid.comune.roma.it",
		KeyFile:  keyFile,
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
	return sp
}