package main

import (
	"fmt"
	"html/template"
	"io"
	"net/http"

	"github.com/italia/spid-go"
)

// This demo application shows how to use the spid package

// This is a stateless object representing your Service Provider. It does
// not hold any information about active sessions, so you can safely store
// it in a global variable.
var sp *spid.SP

// IMPORTANT:
// These variables belong the session of each user. In an actual application
// you would NOT store them as global variables, but you'd store them in the
// user session backed by a cookie, using for example github.com/gorilla/sessions,
// but for simplificy in this example application we are doing this way.
var spidSession *spid.Session
var authnReqID string

func main() {
	// Initialize our SPID object with information about this Service Provider
	sp = &spid.SP{
		EntityID: "https://www.foobar.it/",
		KeyFile:  "sp.key",
		CertFile: "sp.pem",
		AssertionConsumerServices: []string{
			"http://localhost:3000/spid-sso",
		},
		SingleLogoutServices: map[string]spid.SAMLBinding{
			"http://localhost:3000/spid-slo": spid.HTTPRedirect,
		},
		AttributeConsumingServices: []spid.AttributeConsumingService{
			{
				ServiceName: "Service 1",
				Attributes:  []string{"fiscalNumber", "name", "familyName", "dateOfBirth"},
			},
		},
	}

	// Load Identity Providers from their XML metadata
	err := sp.LoadIDPMetadata("idp_metadata")
	if err != nil {
		fmt.Print("Failed to load IdP metadata: ")
		fmt.Println(err)
		return
	}

	// Wire routes and endpoints of our example application
	http.HandleFunc("/", index)
	http.HandleFunc("/metadata", metadata)
	http.HandleFunc("/spid-login", spidLogin)

	// Dance
	fmt.Println("spid-go example application listening on http://localhost:8000")
	http.ListenAndServe(":8000", nil)
}

const tmplLayout = `<!DOCTYPE html>
<html lang="en-US">
<head>
    <title>spid-go Example Application</title>
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" integrity="sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u" crossorigin="anonymous">
    <meta charset="UTF-8" />
</head>
<body>
    <div class="container">
        <h1>spid-go Example Application</h1>
        <div id="content">
        {{ . }}
        </div>
    </div>
</body>
</html>
`

// If we have an active SPID session, display a page with user attributes,
// otherwise show a generic login page containing the SPID button.
func index(w http.ResponseWriter, r *http.Request) {
	if spidSession == nil {
		button := sp.GetButton("/spid-login?idp=%s")
		t := template.Must(template.New("index").Parse(tmplLayout))
		t.Execute(w, template.HTML(button))
	} else {

	}
}

// This endpoint exposes our metadata
func metadata(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/xml")
	io.WriteString(w, sp.Metadata())
}

// This endpoint initiates SSO through the user-chosen Identity Provider.
func spidLogin(w http.ResponseWriter, r *http.Request) {
	// Check that we have the mandatory 'idp' parameter and that it matches
	// an available Identity Provider.
	idp, err := sp.GetIDP(r.URL.Query()["idp"][0])
	if err != nil {
		http.Error(w, "Invalid IdP selected", http.StatusBadRequest)
		return
	}

	// Craft the AuthnRequest.
	authnreq := spid.NewAuthnRequest(sp, idp)
	//authnreq.AcsURL = "http://localhost:3000/spid-sso"
	authnreq.AcsIndex = 0
	authnreq.AttrIndex = 0
	authnreq.Level = 1

	// Save the ID of the Authnreq so that we can check it in the response
	// in order to prevent forgery.
	authnReqID = authnreq.ID

	// Uncomment the following lines to use the HTTP-POST binding instead of HTTP-Redirect:
	///w.Write(authnreq.PostForm())
	///return

	// Redirect user to the IdP using its HTTP-Redirect binding.
	http.Redirect(w, r, authnreq.RedirectURL(), http.StatusSeeOther)
}
