package spidsaml

import (
	"testing"
	"time"
)

func TestInMessage_validateSignatureForPost(t *testing.T) {
	testClock := &Clock{
		instant: time.Date(2021, time.Month(3), 18, 16, 37, 0, 0, time.UTC),
	}
	sp := createSPForTes()
	sp.LoadIDPFromXMLFile("../fixtures/idp_metadata/testenv2_metadata.xml")
	msg := inMessage{
		protocolMessage: protocolMessage{
			SP:    sp,
			IDP:   sp.IDP["http://localhost:8088"],
			clock: testClock,
		}}

	msg.SetXML(createTestXml())

	err := msg.validateSignatureForPost()

	if err != nil {
		t.Error("Failed to validate signature with error ", err)
	}
}
