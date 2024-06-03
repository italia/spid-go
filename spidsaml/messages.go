package spidsaml

// protocolMessage is the base class for all SAML messages
type protocolMessage struct {
	SP    *SP
	IDP   *IDP
	clock *Clock
}
