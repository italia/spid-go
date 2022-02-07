package spidsaml

import (
	"github.com/beevik/etree"
	"testing"
)

func TestMetadata(t *testing.T) {
	sp := createSP()
	doc := etree.NewDocument()
	if doc.ReadFromString(sp.Metadata()) != nil {
		panic("error occurred during parsing metadata file")
	}

	testCases := []struct {
		name        string
		entityPath  string
		entityValue []string
	}{
		{
			name:        "Organization name",
			entityPath:  "/EntityDescriptor/Organization/OrganizationName",
			entityValue: []string{"Foobar"},
		},
		{
			name:        "Organization display name",
			entityPath:  "/EntityDescriptor/Organization/OrganizationDisplayName",
			entityValue: []string{"Foobar"},
		},
		{
			name:        "Organization URL",
			entityPath:  "/EntityDescriptor/Organization/OrganizationURL",
			entityValue: []string{"https://www.foobar.it/"},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for _, e := range doc.FindElements(tc.entityPath) {
				if !contains(tc.entityValue, e.Text()) {
					t.Fail()
				}
			}
		})
	}
}

func createSP() *SP {
	return &SP{
		EntityID: "https://www.foobar.it/",
		KeyFile:  "test/resources/sp.key",
		CertFile: "test/resources/sp.pem",
		AssertionConsumerServices: []string{
			"http://localhost:8000/spid-sso",
		},
		SingleLogoutServices: map[string]SAMLBinding{
			"http://localhost:8000/spid-slo": HTTPRedirect,
		},
		AttributeConsumingServices: []AttributeConsumingService{
			{
				ServiceName: "Service 1",
				Attributes:  []string{"fiscalNumber", "name", "familyName", "dateOfBirth"},
			},
		},
		Organization: Organization{
			Names:        []string{"Foobar"},
			DisplayNames: []string{"Foobar"},
			URLs:         []string{"https://www.foobar.it/"},
		},
	}
}

func contains(array []string, value string) bool {
	for _, el := range array {
		if el == value {
			return true
		}
	}
	return false
}
