package spidsaml

import (
	"testing"
)

func TestNewIDPFromXML(t *testing.T) {
	idp := NewIDPFromXML([]byte(`<?xml version='1.0' encoding='UTF-8'?>
	<EntityDescriptor xmlns:ns0="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ns1="http://www.w3.org/2000/09/xmldsig#" entityID="http://localhost:8088"><ns0:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><ns0:KeyDescriptor use="signing"><ns1:KeyInfo><ns1:X509Data><ns1:X509Certificate>MIICtDCCAZwCCQDQQ+FCxgMN6jANBgkqhkiG9w0BAQsFADAcMQswCQYDVQQGEwJJ
	VDENMAsGA1UEBwwEUm9tYTAeFw0xODA2MjYxMDM5MzBaFw0xOTA2MjYxMDM5MzBa
	MBwxCzAJBgNVBAYTAklUMQ0wCwYDVQQHDARSb21hMIIBIjANBgkqhkiG9w0BAQEF
	AAOCAQ8AMIIBCgKCAQEAudciVxyXnPvTt2r8+3wE9DsibXu9fZwHjji0rOE7FJj8
	fm/2rE0/GfDNyymGv7LHx9vKO8p1Ot4cl0ou/bR70PtJW9tM2ssyWPmHQXmBX84F
	B/IuuOitABEtc3/HsWOyAA23XanCGpv6j6CW8TRjO+bi7nQnW3y/rLuCoTkBihH4
	QGA0bkg8he56BSa3sAPnyO3VLavlYv3yYCQDqR+r2UM1f8gNPTlE5UIQzOYPXv1w
	/YrrFhEx7xUYPh1J2e4J6xRRbZqzvB74QF0t0A0XueCITXLuVQ5eQ1rIWFAL1nwM
	qWvep+3HvDpq0K8nzGFjnut6ElfyyhPp8+/H0zBOkQIDAQABMA0GCSqGSIb3DQEB
	CwUAA4IBAQBw4mfH+WtR/etTVWK1Jy9DXWxAazFViQcVBualTuleRSHZjCv/nyv4
	YbyFlTNarDI+LF+iG2rCABxgY40L6FpN9Gnsa5wijuKs0E6ZAvJ/rYfrYkE8wd0y
	8Z23VeoXD/m8OhwcysMtyM10GxZUtEBnpXDAhAFFDyAACfxAQy+/5u1u5dI0189A
	Fk2EcqcSuA9pQWbzhswlQaSQFBU1nabIU2SwDPfHMwLFVrJdH09RuMSKM4IBNzCi
	Lj5KgqepdFO3+8e0ewiwo8imhTYaTDR3ZXQaTNQt99fhT/LOMUcCR4hH14Cn72X7
	xTPK7hTz4p1D3uXfKT/o1qiql2PAjfl8
	</ns1:X509Certificate></ns1:X509Data></ns1:KeyInfo></ns0:KeyDescriptor><ns0:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="http://localhost:8088/slo" /><ns0:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://localhost:8088/slo" /><ns0:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</ns0:NameIDFormat><ns0:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="http://localhost:8088/sso" /><ns0:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://localhost:8088/sso" /></ns0:IDPSSODescriptor><ns0:Organization><ns0:OrganizationName xml:lang="en">Spid testenv</ns0:OrganizationName><ns0:OrganizationDisplayName xml:lang="en">Spid testenv</ns0:OrganizationDisplayName><ns0:OrganizationURL xml:lang="en">http://www.example.com</ns0:OrganizationURL></ns0:Organization><ns0:ContactPerson contactType="technical"><ns0:GivenName>support</ns0:GivenName><ns0:SurName>support</ns0:SurName><ns0:EmailAddress>technical@example.com</ns0:EmailAddress></ns0:ContactPerson></EntityDescriptor>`))

	if idp.EntityID != "http://localhost:8088" {
		t.Error("Failed to parse entityID")
	}
	if idp.SSOURLs[HTTPPost] != "http://localhost:8088/sso" {
		t.Error("Failed to parse SingleSignOnService")
	}
	if idp.SLOReqURLs[HTTPPost] != "http://localhost:8088/slo" {
		t.Error("Failed to parse SingleLogoutService")
	}
}

func TestSP_LoadIDPMetadata(t *testing.T) {
	sp := &SP{}

	if err := sp.LoadIDPMetadata("../sample_data/idp_metadata"); err != nil {
		t.Error(err)
	}

	idpIds := []string{
		"https://identity.infocert.it",
		"https://posteid.poste.it",
		"https://spid.register.it",
		"https://identity.sieltecloud.it",
		"https://loginspid.aruba.it",
		"https://spid.intesa.it",
		"https://id.lepida.it/idp/shibboleth",
		"https://idp.namirialtsp.com/idp",
		"https://login.id.tim.it/affwebservices/public/saml2sso",
	}

	if nrOfMetadata := len(sp.IDP); nrOfMetadata != len(idpIds) {
		t.Errorf("Expected metadata for %d IDP but fond %d", len(idpIds), nrOfMetadata)
	}

	for _, k := range idpIds {
		if idp, _ := sp.GetIDP(k); idp == nil {
			t.Errorf("Metadata for %s not found", k)
		}
	}
}

func TestSP_AnIDPCanHaveMultipleCertificates(t *testing.T) {
	sp := &SP{}

	if err := sp.LoadIDPFromXMLFile("../sample_data/idp_metadata/aruba.xml"); err != nil {
		t.Error(err)
	}

	nrOfCertificates := len(sp.IDP["https://loginspid.aruba.it"].Certs)
	if nrOfCertificates != 2 {
		t.Error("Expected 2 cerificates, but got ", nrOfCertificates)
	}
}
