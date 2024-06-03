package spidsaml

import (
	dsig "github.com/russellhaering/goxmldsig"
)

// protocolMessage is the base class for all SAML messages
type protocolMessage struct {
	SP    *SP
	IDP   *IDP
	clock *dsig.Clock
}
