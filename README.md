# spid-go

Golang package for SPID authentication

[![Join the #spid-go channel](https://img.shields.io/badge/Slack%20channel-%23spid--go-blue.svg?logo=slack)](https://developersitalia.slack.com/messages/CCMJE9631)
[![Get invited](https://slack.developers.italia.it/badge.svg)](https://slack.developers.italia.it/)
[![SPID on forum.italia.it](https://img.shields.io/badge/Forum-SPID-blue.svg)](https://forum.italia.it/c/spid) [![CircleCI](https://circleci.com/gh/italia/spid-go.svg?style=svg)](https://circleci.com/gh/italia/spid-go)

This Go package is aimed at implementing SPID Service Providers. [SPID](https://www.spid.gov.it/) is the Italian digital identity system, which enables citizens to access all public services with single set of credentials. This module provides a layer of abstraction over the SAML protocol by exposing just the subset required in order to implement SPID authentication in a web application.

## Getting Started

The [example/](example/) directory contains a demo web application. Just follow these steps in order to test it quickly:

1. Install the [go-xmlsec](https://github.com/crewjam/go-xmlsec) dependency. While `go get` should get everything else you need, go-xmlsec depends on a C library so you should install it manually. It's quick. See its [README](https://github.com/crewjam/go-xmlsec) for details. (You might need to run `export CGO_CFLAGS_ALLOW=".*"` first to make it compile correctly.)

2. Run the demo application:
   ```bash
   cd example/
   go run service.go
   ```

3. Connect to [http://localhost:8000/metadata](http://localhost:8000/metadata) and grab the metadata of the demo Service Provider.

4. Configure [spid-testenv2](https://github.com/italia/spid-testenv2) and load the above Service Provider metadata into it.

5. Get the metadata file of the spid-testenv2 demo Identity Provider (its default location is [http://localhost:8088/metadata](http://localhost:8088/metadata)) and save it in the example/idp_metadata directory.

6. Launch [http://localhost:8000](http://localhost:8000) and enjoy your SPID demo.

## Using different keys

If you want to use different keys/certificate:

1. Use the [SPID compliant certificate builder](https://github.com/italia/spid-compliant-certificates)
   
2. The above tool will create a [PKCS#8](https://en.wikipedia.org/wiki/PKCS) private key (key.pem) and a certificate (crt.pem). For this example we need to extract the RSA private key from the PKCS#8 file. In order to do this, we need to run this command:
   ```bash
   openssl rsa -in key.pem -out key.rsa.pem
   ```

## Features

|<img src="https://github.com/italia/spid-graphics/blob/master/spid-logos/spid-logo-c-lb.png?raw=true" width="100" /><br />_Compliance with [SPID regulations](http://www.agid.gov.it/sites/default/files/circolari/spid-regole_tecniche_v1.pdf) (for Service Providers)_||
|:---|:---|
|**Metadata:**||
|parsing of IdP XML metadata (1.2.2.4)|✓|
|support for multiple signing certificates in IdP XML metadata (1.2.2.4)||
|parsing of AA XML metadata (2.2.4)||
|SP XML metadata generation (1.3.2)|✓|
|**AuthnRequest generation (1.2.2.1):**||
|generation of AuthnRequest XML|✓|
|HTTP-Redirect binding|✓|
|HTTP-POST binding|✓|
|`AssertionConsumerServiceURL` customization|✓|
|`AssertionConsumerServiceIndex` customization|✓|
|`AttributeConsumingServiceIndex` customization|✓|
|`AuthnContextClassRef` (SPID level) customization|✓|
|`RequestedAuthnContext/@Comparison` customization|✓|
|`RelayState` customization (1.2.2)|✓|
|**Response/Assertion parsing**||
|verification of `Signature` value (if any)|✓|
|verification of `Signature` certificate (if any) against IdP/AA metadata|✓|
|verification of `Assertion/Signature` value|✓|
|verification of `Assertion/Signature` certificate against IdP/AA metadata|✓|
|verification of `SubjectConfirmationData/@Recipient`|✓|
|verification of `SubjectConfirmationData/@NotOnOrAfter`|✓|
|verification of `SubjectConfirmationData/@InResponseTo`|✓|
|verification of `Issuer`|✓|
|verification of `Assertion/Issuer`|✓|
|verification of `Destination`|✓|
|verification of `Conditions/@NotBefore`|✓|
|verification of `Conditions/@NotOnOrAfter`|✓|
|verification of `Audience`|✓|
|parsing of Response with no `Assertion` (authentication/query failure)|✓|
|parsing of failure `StatusCode` (Requester/Responder)|✓|
|**Response/Assertion parsing for SSO (1.2.1, 1.2.2.2, 1.3.1):**||
|parsing of `NameID`|✓|
|parsing of `AuthnContextClassRef` (SPID level)|✓|
|parsing of attributes|✓|
|**Response/Assertion parsing for attribute query (2.2.2.2, 2.3.1):**||
|parsing of attributes| |
|**LogoutRequest generation (for SP-initiated logout):**||
|generation of LogoutRequest XML|✓|
|HTTP-Redirect binding|✓|
|HTTP-POST binding|✓|
|**LogoutResponse parsing (for SP-initiated logout):**||
|parsing of LogoutResponse XML|✓|
|verification of `Response/Signature` value (if any)|✓|
|verification of `Response/Signature` certificate (if any) against IdP metadata|✓|
|verification of `Issuer`|✓|
|verification of `Destination`|✓|
|PartialLogout detection|✓|
|**LogoutRequest parsing (for third-party-initiated logout):**||
|parsing of LogoutRequest XML|✓|
|verification of `Response/Signature` value (if any)|✓|
|verification of `Response/Signature` certificate (if any) against IdP metadata|✓|
|verification of `Issuer`|✓|
|verification of `Destination`|✓|
|parsing of `NameID`|✓|
|**LogoutResponse generation (for third-party-initiated logout):**||
|generation of LogoutResponse XML|✓|
|HTTP-Redirect binding|✓|
|HTTP-POST binding|✓|
|PartialLogout customization|✓|
|**AttributeQuery generation (2.2.2.1):**||
|generation of AttributeQuery XML| |
|SOAP binding (client)| |

|<img src="https://github.com/italia/spid-graphics/blob/master/spid-logos/spid-logo-c-lb.png?raw=true" width="100" /><br />_Compliance with [SPID regulations](http://www.agid.gov.it/sites/default/files/circolari/spid-regole_tecniche_v1.pdf) (for Attribute Authorities)_||
|:---|:---|
|**Metadata:**||
|parsing of SP XML metadata (1.3.2)| |
|AA XML metadata generation (2.2.4)| |
|**AttributeQuery parsing (2.2.2.1):**||
|parsing of AttributeQuery XML| |
|verification of `Signature` value| |
|verification of `Signature` certificate against SP metadata| |
|verification of `Issuer`| |
|verification of `Destination`| |
|parsing of `Subject/NameID`| |
|parsing of requested attributes| |
|**Response/Assertion generation (2.2.2.2):**||
|generation of `Response/Assertion` XML| |
|Signature| |

### More features

* [ ] Generation of SPID button markup

## See also

* [SPID page](https://developers.italia.it/it/spid) on Developers Italia

## Authors

* [Alessandro Ranellucci](https://github.com/alranel) (maintainer) - [Team per la Trasformazione Digitale](https://teamdigitale.governo.it/) - Presidenza del Consiglio dei Ministri
  * [alranel@teamdigitale.governo.it](alranel@teamdigitale.governo.it)
