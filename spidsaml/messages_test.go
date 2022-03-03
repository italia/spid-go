package spidsaml

import (
	"bytes"
	"testing"
)

func TestInMessage_validateSignatureForPost(t *testing.T) {
	firstBytesOfSignature := []byte("ocC")
	cases := []struct {
		xml       []byte
		returnErr bool
		name      string
	}{
		{
			xml:       createTestXml(),
			returnErr: false,
			name:      "Can recognize a valid signed document",
		},
		{
			xml:       bytes.Replace(createTestXml(), firstBytesOfSignature, []byte("xxx"), 1),
			returnErr: true,
			name:      "Can recognize an invalid signed document",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sp := createSPForTes()
			sp.LoadIDPFromXMLFile("../fixtures/idp_metadata/testenv2_metadata.xml")
			msg := inMessage{
				protocolMessage: protocolMessage{
					SP:  sp,
					IDP: sp.IDP["http://localhost:8088"],
				}}

			msg.SetXML(tc.xml)

			err := msg.validateSignatureForPost()

			if err != nil && !tc.returnErr {
				t.Error("Failed to validate response with error ", err)
			}

			if err == nil && tc.returnErr {
				t.Error("Verification should fail")
			}
		})
	}
}

