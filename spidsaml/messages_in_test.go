package spidsaml

import (
	"bytes"
	"testing"
	"time"

	dsig "github.com/russellhaering/goxmldsig"
)

func TestInMessage_validateSignatureForPost(t *testing.T) {
	firstBytesOfSignature := []byte("ocC")
	cases := []struct {
		testClock *dsig.Clock
		xml       []byte
		returnErr bool
		name      string
	}{
		{
			testClock: dsig.NewFakeClockAt(time.Date(2021, time.Month(3), 18, 16, 37, 0, 0, time.UTC)),
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
			sp.LoadIDPFromXMLFile("../sample_data/test_idp/testenv2_metadata.xml")
			msg := inMessage{
				protocolMessage: protocolMessage{
					SP:    sp,
					IDP:   sp.IDP["http://localhost:8088"],
					clock: tc.testClock,
				}}

			msg.SetXML(tc.xml)

			err := msg.validateSignatureForPost(msg.doc.Root())

			if err != nil && !tc.returnErr {
				t.Error("Failed to validate response with error ", err)
			}

			if err == nil && tc.returnErr {
				t.Error("Verification should fail")
			}
		})
	}
}
