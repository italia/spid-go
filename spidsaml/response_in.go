package spidsaml

import (
	"fmt"
	"strconv"
)

// Response represents an incoming SPID Response/Assertion message. We get such messages after an AuthnRequest (Single Sign-On).
type Response struct {
	inMessage
}

// ParseResponseB64 accepts a Base64-encoded XML payload and parses it as a
// Response/Assertion.
// Validation is performed (see the documentation for the Response::validate()
// method), so this method may return an error.
// A second argument can be supplied, containing the C<ID> of the request message;
// in this case validation will also check the InResponseTo attribute.
func (sp *SP) ParseResponseB64(payload string, inResponseTo string) (*Response, error) {
	response := &Response{}
	response.SP = sp
	err := response.parseB64(payload)
	if err != nil {
		return nil, err
	}

	err = response.validate(inResponseTo)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// validate performs validation on this message.
func (response *Response) validate(inResponseTo string) error {
	err := response.inMessage.validate()
	if err != nil {
		return err
	}

	// TODO: validate IssueInstant

	if inResponseTo != response.InResponseTo() {
		return fmt.Errorf("Invalid InResponseTo: '%s' (expected: '%s')",
			response.InResponseTo(), inResponseTo)
	}

	// As of current SPID spec, Destination might be populated with the entityID
	// instead of the ACS URL
	destination := response.Destination()
	knownDestination := false
	for _, acs := range response.SP.AssertionConsumerServices {
		if acs == destination {
			knownDestination = true
			break
		}
	}
	if !knownDestination {
		return fmt.Errorf("Invalid Destination: '%s'", destination)
	}

	/*
		TODO: port this

				if ($self->success) {
			        # We expect to have an <Assertion> element

			        croak sprintf "Response/Issuer (%s) does not match Assertion/Issuer (%s)",
			            $self->Issuer, $self->Assertion_Issuer
			            if $self->Issuer ne $self->Assertion_Issuer;

			        croak sprintf "Invalid Audience: '%s' (expected: '%s')",
			            $self->Assertion_Audience, $self->_spid->sp_entityid
			            if $self->Assertion_Audience ne $self->_spid->sp_entityid;

			        croak sprintf "Invalid InResponseTo: '%s' (expected: '%s')",
			            $self->Assertion_InResponseTo, $args{in_response_to}
			            if $self->Assertion_InResponseTo ne $args{in_response_to};

			        # this validates all the signatures in the given XML, and requires that at least one exists
			        my $pubkey = Crypt::OpenSSL::RSA->new_public_key($self->_idp->cert->pubkey);
			        Mojo::XMLSig::verify($self->xml, $pubkey)
			            or croak "Signature verification failed";

			        # SPID regulations require that Assertion is signed, while Response can be not signed
			        croak "Response/Assertion is not signed"
			            if $xpath->findnodes('/samlp:Response/saml:Assertion/dsig:Signature')->size == 0;

			        my $now = DateTime->now;

			        # exact match is ok
			        croak sprintf "Invalid NotBefore: '%s' (now: '%s')",
			            $self->NotBefore->iso8601, $now->iso8601
			            if DateTime->compare($now, $self->NotBefore) < 0;

			        # exact match is *not* ok
			        croak sprintf "Invalid NotOnOrAfter: '%s' (now: '%s')",
			            $self->NotOnOrAfter->iso8601, $now->iso8601
			            if DateTime->compare($now, $self->NotOnOrAfter) > -1;

			        # exact match is *not* ok
			        croak sprintf "Invalid SubjectConfirmationData/NotOnOrAfter: '%s' (now: '%s')",
			            $self->SubjectConfirmationData_NotOnOrAfter->iso8601, $now->iso8601
			            if DateTime->compare($now, $self->SubjectConfirmationData_NotOnOrAfter) > -1;

			        croak "Invalid SubjectConfirmationData/\@Recipient'"
			            if !grep { $_ eq $self->Assertion_Recipient } @{$self->_spid->sp_assertionconsumerservice};

			        croak "Mismatch between Destination and SubjectConfirmationData/\@Recipient"
			            if $self->Destination ne $self->Assertion_Recipient;
			    } else {
			        # Authentication failed, so we expect no <Assertion> element.
				}
	*/

	return nil
}

// StatusCode returns the value of the <StatusCode> element.
func (msg *inMessage) Success() bool {
	return msg.StatusCode() == "urn:oasis:names:tc:SAML:2.0:status:Success"
}

// Session returns a Session object populated with useful information from this
// Response/Assertion. You might want to store this object along with the user
// session of your application, so that you can use it for generating the
// LoginRequest
func (msg *inMessage) Session() *Session {
	return &Session{
		IDPEntityID:  msg.IDP.EntityID,
		NameID:       msg.NameID(),
		SessionIndex: msg.SessionIndex(),
		AssertionXML: msg.XML,
		Level:        msg.Level(),
		Attributes:   msg.Attributes(),
	}
}

// StatusCode returns the value of the <StatusCode> element.
func (msg *inMessage) StatusCode() string {
	return msg.doc.FindElement("/Response/Status/StatusCode").SelectAttrValue("Value", "")
}

// StatusCode2 returns the value of the <StatusCode><StatusCode> sub-element.
func (msg *inMessage) StatusCode2() string {
	return msg.doc.FindElement("/Response/Status/StatusCode/StatusCode").SelectAttrValue("Value", "")
}

// StatusMessage returns the value of the <StatusMessage> element.
func (msg *inMessage) StatusMessage() string {
	return msg.doc.FindElement("/Response/Status/StatusMessage").Text()
}

// NameID returns the value of the <NameID> element.
func (msg *inMessage) NameID() string {
	return msg.doc.FindElement("/Response/Assertion/Subject/NameID").Text()
}

// SessionIndex returns the value of the SessionIndex attribute.
func (msg *inMessage) SessionIndex() string {
	return msg.doc.FindElement("/Response/Assertion/AuthnStatement").SelectAttrValue("SessionIndex", "")
}

// Level returns the SPID level specified in the assertion.
func (msg *inMessage) Level() int {
	ref := msg.doc.FindElement("/Response/Assertion/AuthnStatement/AuthnContext/AuthnContextClassRef").Text()
	i, err := strconv.Atoi(string(ref[len(ref)-1]))
	if err != nil {
		return 0
	}
	return i
}

// Attributes returns the attributes carried by the assertion.
func (msg *inMessage) Attributes() map[string]string {
	attributes := make(map[string]string)
	for _, e := range msg.doc.FindElements("/Response/Assertion/AttributeStatement/Attribute") {
		attributes[e.SelectAttr("Name").Value] = e.FindElement("AttributeValue").Text()
	}
	return attributes
}
