package spidsaml

import (
	"fmt"
	"net/http"
)

// LogoutResponseIn represents an incoming LogoutResponse. You can use this to
// parse the response coming from the Identity Provider after you sent a
// LogoutRequest for a SP-initiated logout. You are not supposed to instantiate
// this directly; use ParseLogoutResponse() instead.
type LogoutResponseIn struct {
	inMessage
}

// ParseLogoutResponse parses an http.Request and instantiates a LogoutResponseIn.
func (sp *SP) ParseLogoutResponse(r *http.Request, inResponseTo string) (*LogoutResponseIn, error) {
	response := &LogoutResponseIn{}
	response.SP = sp
	err := response.parse(r, "SAMLResponse")
	if err != nil {
		return nil, err
	}
	fmt.Printf("%s\n", response.XML)
	err = response.validate(r, inResponseTo)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// validate performs validation on this message.
func (logoutres *LogoutResponseIn) validate(r *http.Request, inResponseTo string) error {
	err := logoutres.inMessage.validate()
	if err != nil {
		return err
	}

	err = logoutres.validateSignature(r, "SAMLResponse")
	if err != nil {
		return err
	}

	if inResponseTo != logoutres.InResponseTo() {
		return fmt.Errorf("invalid InResponseTo: '%s' (expected: '%s')",
			logoutres.InResponseTo(), inResponseTo)
	}

	// As of current SPID spec, Destination might be populated with the entityID
	// instead of the ACS URL
	destination := logoutres.Destination()
	knownDestination := destination == logoutres.SP.EntityID
	for sls := range logoutres.SP.SingleLogoutServices {
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
