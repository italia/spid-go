package spidsaml

import (
	"bytes"
	"net/http"
	"testing"
)

func TestSP_ParseLogoutResponse(t *testing.T) {
	cases := []struct {
		signature string
		returnErr bool
		name      string
	}{
		{
			signature: "FR8vhaEGNMmj7cPj+LBsLvMFAzt2GpRG7PG3vX2GxQOToJfPcvBKOnWteoCltzexXcPP1u8q0U1LNQwJWfCgpzaX6UCYmdwlhO8BbKswVQnU1hI6X1zUiuezDF70zHefljDu4qFOR9lXU9SRM2LDPlXd/pguF+2PlfD2tLayWwoLWSOtYhatqwGBqFRDrSJv7uEuklX3nWtifnt6V86ts3aZYWXOZNaQLyj2rJiMbNk4c0/pqRLoZwNcEqIho6xGSfu64Ir5+mIKeVVbhAnlSWANr91fpTz0g+cd0NBOcirPg+RM4ljP0FrAvMvmOe1E2gjl9n1U4yfzEmi1GaxpMQ==",
			returnErr: false,
			name:      "Can recognize a valid signed logout response",
		},
		{
			signature: "1R8vhaEGNMmj7cPj+LBsLvMFAzt2GpRG7PG3vX2GxQOToJfPcvBKOnWteoCltzexXcPP1u8q0U1LNQwJWfCgpzaX6UCYmdwlhO8BbKswVQnU1hI6X1zUiuezDF70zHefljDu4qFOR9lXU9SRM2LDPlXd/pguF+2PlfD2tLayWwoLWSOtYhatqwGBqFRDrSJv7uEuklX3nWtifnt6V86ts3aZYWXOZNaQLyj2rJiMbNk4c0/pqRLoZwNcEqIho6xGSfu64Ir5+mIKeVVbhAnlSWANr91fpTz0g+cd0NBOcirPg+RM4ljP0FrAvMvmOe1E2gjl9n1U4yfzEmi1GaxpMQ==",
			returnErr: true,
			name:      "Can recognize an invalid signed logout response",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sp := createSPForTes()
			sp.LoadIDPFromXMLFile("../fixtures/idp_metadata/testenv2_metadata.xml")


			request, err := http.NewRequest(http.MethodGet, logoutUrl(), bytes.NewReader(creatTestLogoutResponseXml()))

			q := request.URL.Query()
			q.Add("SAMLResponse", "hZLdauMwEIXv+xRC94klRXYcEQeWLYVCWmgTStmbMpYnicCWjEcm7dvXMf2nZC91dObozIeWBE3dmnXYhz7eI7XBE7LnpvZkxquC9503AciR8dAgmWjN5s/N2qipMG0XYrCh5uwBO3LBF3yQObu+LLirnkCX88VsJ9I5QIlQWplWkKpcIWZWWzW3CxBlqoYBoh6vPUXwccgQSk7EbKLkVmZGpibV/zi7RIrOQxyfOcTYmiSpg4X6ECiaXAiRUOuqCdVhCPTv22xDwZ8w31Uo9EKVArScS12moCtZzdJMZlpnfHXB2PK0sRmrdF8YnEcARNidOvG3kWf6aHc8HqfH2TR0+0QJIZPHm/XGHrCBT6/7v3niRi4WObsKXQPxfKGTMlDYjVaDPrr4wtntoN71ULudw67gFBqMB+f3fPULyTxfJl9YfLBpzSZC7Okk/JD+hgrZA9Q9nm9Ho9tsemuRiCdjdvI9/P38/VeuLl4B")
			q.Add("SigAlg", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
			q.Add("Signature", tc.signature)
			request.URL.RawQuery = q.Encode()

			_, err = sp.ParseLogoutResponse(request, "_e8fde0492b0a41714b5a4d1d35616446")

			if err != nil && !tc.returnErr {
				t.Error("Failed to validate response with error ", err)
			}

			if err == nil && tc.returnErr {
				t.Error("Verification should fail")
			}
		})
	}
}

func logoutUrl() string {
	return "http://localhost:8000/spid-slo"
}

func creatTestLogoutResponseXml() []byte {
	return []byte(`<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Version="2.0" ID="id_a4b793f057aabeabc15da5282ee6c4c27c9a0b52" IssueInstant="2021-03-21T16:15:54Z" Destination="http://localhost:8000/spid-slo" InResponseTo="_e8fde0492b0a41714b5a4d1d35616446">
  <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity" NameQualifier="something">http://localhost:8088</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
</samlp:LogoutResponse>
`)
}