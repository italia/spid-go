package spidsaml

import (
	"fmt"
	"net/http"
)

// LogoutRequestIn represents an incoming LogoutRequest. You can use this to
// parse a logout request in case the user initiated a logout procedure
// elsewhere and an Identity Provider is requesting logout to you. You are not
// supposed to instantiate this directly; use ParseLogoutRequest() instead.
type LogoutRequestIn struct {
	inMessage
}

// ParseLogoutRequest parses an http.Request and instantiates a LogoutRequestIn.
func (sp *SP) ParseLogoutRequest(r *http.Request) (*LogoutRequestIn, error) {
	response := &LogoutRequestIn{}
	response.SP = sp
	err := response.read(r, "SAMLRequest")
	if err != nil {
		return nil, err
	}

	return response, nil
}

// validate performs validation on this message.
func (logoutreq *LogoutRequestIn) Validate(r *http.Request) error {
	err := logoutreq.inMessage.matchIncomingIDP()
	if err != nil {
		return err
	}

	err = logoutreq.validateSignature(r, "SAMLRequest")
	if err != nil {
		return err
	}

	// As of current SPID spec, Destination might be populated with the entityID
	// instead of the ACS URL
	destination := logoutreq.Destination()
	knownDestination := destination == logoutreq.SP.EntityID
	for sls := range logoutreq.SP.SingleLogoutServices {
		if sls == destination {
			knownDestination = true
			break
		}
	}
	if !knownDestination {
		return fmt.Errorf("invalid Destination: '%s'", destination)
	}

	return nil
}

// SessionIndex returns the value of the <SessionIndex> element.
func (logoutreq *LogoutRequestIn) SessionIndex() string {
	return logoutreq.doc.FindElement("/LogoutRequest/SessionIndex").Text()
}
