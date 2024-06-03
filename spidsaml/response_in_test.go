package spidsaml

import (
	"testing"
	"time"
)

func TestResponse_verify_response_from_IDP(t *testing.T) {
	const REAL_REQUESTID = "_56b83874b956b3140a8d6767072f546c"
	cases := []struct {
		testClock *Clock
		requestId string
		returnErr bool
		name      string
	}{
		{
			testClock: &Clock{
				instant: time.Date(2021, time.Month(3), 18, 16, 37, 0, 0, time.UTC),
			},
			requestId: REAL_REQUESTID,
			returnErr: false,
			name:      "Can verfy a response in the correct time interval",
		},
		{
			testClock: nil,
			requestId: REAL_REQUESTID,
			returnErr: true,
			name:      "Using the real clock should give error because time has gone by",
		},
		{
			testClock: nil,
			requestId: "aWrongRequestId",
			returnErr: true,
			name:      "Can check if the response is for the wrong requestId",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sp := createSPForTes()
			sp.LoadIDPFromXMLFile("../sample_data/idp_metadata/testenv2_metadata.xml")
			response := &Response{
				inMessage: inMessage{
					protocolMessage: protocolMessage{
						SP:    sp,
						IDP:   sp.IDP["http://localhost:8088"],
						clock: tc.testClock,
					},
				},
			}

			response.SetXML(createTestXml())

			err := response.validate(tc.requestId)
			if err != nil && !tc.returnErr {
				t.Error("Failed to validate response with error ", err)
			}

			if err == nil && tc.returnErr {
				t.Error("Verification should fail")
			}
		})
	}
}

func createTestXml() []byte {
	return []byte(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Version="2.0" ID="id_81e883cc761a49dbec5fa4b45f9f24886ad67e18" IssueInstant="2021-03-18T16:38:42Z" Destination="http://localhost:8000/spid-sso" InResponseTo="_56b83874b956b3140a8d6767072f546c">
  <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity" NameQualifier="http://localhost:8088">http://localhost:8088</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#id_81e883cc761a49dbec5fa4b45f9f24886ad67e18"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>w6dcrHpUy7K/8+TTUw7pICpdOPwGERXotEGzSImMtLc=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>ocCFAtPJqtVaiHiN4LXLXGAJQMbJATgoN5s+WaJpQxrkfpTmUjyB6OAWxWb95izVz7113PaKVI/HNqn7q6reDSlPjDzBBzOa4hW/gUGev9vINzydxbk3Dcq/umDr1W+BBPsSD/pUh1u/TbEc5M3jF+e3zgCSbBYB6Uo/93MRt78Jn7ElmyAM+MDAeqoAcfEPn8yJ0gK51lFq3j/om7GivvDC2w9MzMD7JR6RdAgOrWw5JCBa/j7XvHZPrO8uPNbr0d3kB3FYBKJPMqRRp55OTDuNP8HYI1bNWI2ydsqiTY80YS2S4O4GNjon8q8vzoFDoElzEWyDF+LrOVPVrSBPQQ==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIC+zCCAeOgAwIBAgIUOlit7s5T4c8mTVXS1pkjdbSYW0QwDQYJKoZIhvcNAQEL
BQAwDTELMAkGA1UEBhMCSVQwHhcNMjEwMzExMDk1MTExWhcNMjEwNDEwMDk1MTEx
WjANMQswCQYDVQQGEwJJVDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AOy6ndLA6rKwszrE1H1+2ej7YgD+B/yyRAbV63bWQeG9aqqkFlp3b4HMqDuONmUR
B5Jb4Ym9idz4BcCrMN5clIiczIYiZclkCvY+DgUUEpZ7ayhG27d5Ae5nNkVs7o4a
1IXU+wjcq7KZeOws1dYrCbkTw6VtTHBxtWSQDwRxJuTWkcHz6+BXjyvPo+YJY5Dq
vtapaYOh7v4M2OOmC/aX0ysLOAdQzJmDhtE8ERFjZ8+Uh4asv91hloGbncFRnxuL
9SyqN8Vd+yuFESg70mLV04aD6/jxUXgFqcOt68I72TeMfX90+HXg3yn87aCdNj26
THMpll7mB+zMF9bxpUyH5nsCAwEAAaNTMFEwHQYDVR0OBBYEFC3vWqmi+pxISKTQ
Gbwl/qA8p1jhMB8GA1UdIwQYMBaAFC3vWqmi+pxISKTQGbwl/qA8p1jhMA8GA1Ud
EwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAM6vzxMfXXXvOWcYmKm1+Dbq
X+j6a7oOYhvURHDOfpyUQMM26OruRlkBtDSAohn1h/OR8ZwnqKP0OwW18OGSpH88
5n/DSTp5HPpWXZ0YnOviDR5THrRkZSstXaD8EahacrlpX38rU4QxE7dtpuzgrEcX
gYstG0RD3CCFLGnhCUFBRdJO7S3HAkJfeCgJ5+lGQoRGwXqBkssvkP2PyA9Qbku3
rDq4DSBBx4fQXGC4HUMnbv4Y2iZHu7W2S8/miJ2tIfCoikYl8XCzVosrIhjg67UD
8LFlGRVdaBsK01vwhv1aMQ1RD3buDKkhUGcV4hxLBRPNZzddgwNOvzKet5qN6w0=
</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Version="2.0" ID="id_90afff83dec444a02a22244d848782563717eb25" IssueInstant="2021-03-18T16:38:42Z">
    <saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity" NameQualifier="http://localhost:8088">http://localhost:8088</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#id_90afff83dec444a02a22244d848782563717eb25"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>elMFm2Jf3i4Wdr4U0pAQbtRdsgcA3y1qqoB/FIjZd/Y=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>XdARX5lGT/nzX9ttA3eIEdps9s2G5NvvBVqo/RofzHQSaxKJZHUZoUtmMcGjIT+nZhGihIlW4lKo5IflL7GCQI7eHhFSNglUaAeyoPcmQwt3X57kMSq/0F0udfdL1OaVqwcwExpUy9IOFDdjeoMTBPAhHhv9/z3pKQPrktCHPfX3KKlO2auOhdK4woDfErljR5jq7kz/tgdaPSy2+3xu9QGLZaO1WHWa2wElSFKCmWarRJpgC/9qT0IxnnEoX+z+UBGCz5OeeYqRLz3Etmlk3fnjLS0J0n+7Ae6bQPEwoxpXDz3Tc83hke4XONDTZ1GASFH3h4H2XqhIBpbEJxYdkA==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIC+zCCAeOgAwIBAgIUOlit7s5T4c8mTVXS1pkjdbSYW0QwDQYJKoZIhvcNAQEL
BQAwDTELMAkGA1UEBhMCSVQwHhcNMjEwMzExMDk1MTExWhcNMjEwNDEwMDk1MTEx
WjANMQswCQYDVQQGEwJJVDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AOy6ndLA6rKwszrE1H1+2ej7YgD+B/yyRAbV63bWQeG9aqqkFlp3b4HMqDuONmUR
B5Jb4Ym9idz4BcCrMN5clIiczIYiZclkCvY+DgUUEpZ7ayhG27d5Ae5nNkVs7o4a
1IXU+wjcq7KZeOws1dYrCbkTw6VtTHBxtWSQDwRxJuTWkcHz6+BXjyvPo+YJY5Dq
vtapaYOh7v4M2OOmC/aX0ysLOAdQzJmDhtE8ERFjZ8+Uh4asv91hloGbncFRnxuL
9SyqN8Vd+yuFESg70mLV04aD6/jxUXgFqcOt68I72TeMfX90+HXg3yn87aCdNj26
THMpll7mB+zMF9bxpUyH5nsCAwEAAaNTMFEwHQYDVR0OBBYEFC3vWqmi+pxISKTQ
Gbwl/qA8p1jhMB8GA1UdIwQYMBaAFC3vWqmi+pxISKTQGbwl/qA8p1jhMA8GA1Ud
EwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAM6vzxMfXXXvOWcYmKm1+Dbq
X+j6a7oOYhvURHDOfpyUQMM26OruRlkBtDSAohn1h/OR8ZwnqKP0OwW18OGSpH88
5n/DSTp5HPpWXZ0YnOviDR5THrRkZSstXaD8EahacrlpX38rU4QxE7dtpuzgrEcX
gYstG0RD3CCFLGnhCUFBRdJO7S3HAkJfeCgJ5+lGQoRGwXqBkssvkP2PyA9Qbku3
rDq4DSBBx4fQXGC4HUMnbv4Y2iZHu7W2S8/miJ2tIfCoikYl8XCzVosrIhjg67UD
8LFlGRVdaBsK01vwhv1aMQ1RD3buDKkhUGcV4hxLBRPNZzddgwNOvzKet5qN6w0=
</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient" NameQualifier="http://localhost:8088">id_2bafb0d58a369f2ea20b399ba29781bc221a5e46</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData Recipient="http://localhost:8000/spid-sso" NotOnOrAfter="2021-03-18T16:40:42Z" InResponseTo="_56b83874b956b3140a8d6767072f546c"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2021-03-18T16:36:42Z" NotOnOrAfter="2021-03-18T16:40:42Z">
      <saml:AudienceRestriction>
        <saml:Audience>https://spid.comune.roma.it</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="2021-03-18T16:38:42Z" SessionIndex="id_0456de0f359c4dfe0b6af6ef09d5ae3dd50364e9">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>https://www.spid.gov.it/SpidL1</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="fiscalNumber">
        <saml:AttributeValue xsi:type="xs:string">TINIT-MNTTMS98D45G258G</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="name">
        <saml:AttributeValue xsi:type="xs:string">Tommaso</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="familyName">
        <saml:AttributeValue xsi:type="xs:string">Monti</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="dateOfBirth">
        <saml:AttributeValue xsi:type="xs:date">1998-04-05</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>`)
}
