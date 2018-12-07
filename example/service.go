package main

import (
	"fmt"
	"html/template"
	"io"
	"net/http"

	"../spidsaml"
)

// This demo application shows how to use the spid package

// This is a stateless object representing your Service Provider. It does
// not hold any information about active sessions, so you can safely store
// it in a global variable.
var sp *spidsaml.SP

// IMPORTANT:
// These variables belong the session of each user. In an actual application
// you would NOT store them as global variables, but you'd store them in the
// user session backed by a cookie, using for example github.com/gorilla/sessions,
// but for simplificy in this example application we are doing this way.
var spidSession *spidsaml.Session
var authnReqID string

func main() {
	// Initialize our SPID object with information about this Service Provider
	sp = &spidsaml.SP{
		EntityID: "https://www.foobar.it/",
		KeyFile:  "sp.key",
		CertFile: "sp.pem",
		AssertionConsumerServices: []string{
			"http://localhost:8000/spid-sso",
		},
		SingleLogoutServices: map[string]spidsaml.SAMLBinding{
			"http://localhost:8000/spid-slo": spidsaml.HTTPRedirect,
		},
		AttributeConsumingServices: []spidsaml.AttributeConsumingService{
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
	http.HandleFunc("/spid-sso", spidSSO)

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
		fmt.Fprintf(w, spidSession.Attributes["name"])
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
	authnreq := sp.NewAuthnRequest(idp)
	//authnreq.AcsURL = "http://localhost:3000/spid-sso"
	authnreq.AcsIndex = 0
	authnreq.AttrIndex = 0
	authnreq.Level = 1

	// Save the ID of the Authnreq so that we can check it in the response
	// in order to prevent forgery.
	authnReqID = authnreq.ID

	// Uncomment the following lines to use the HTTP-POST binding instead of HTTP-Redirect:
	//w.Write(authnreq.PostForm())
	//return

	// Redirect user to the IdP using its HTTP-Redirect binding.
	http.Redirect(w, r, authnreq.RedirectURL(), http.StatusSeeOther)
}

// This endpoint exposes an AssertionConsumerService for our Service Provider.
// During SSO, the Identity Provider will redirect user to this URL POSTing
// the resulting assertion.
func spidSSO(w http.ResponseWriter, r *http.Request) {
	// Parse and verify the incoming assertion. This may throw exceptions so we
	// enclose it in an eval {} block.
	r.ParseForm()
	response, err := sp.ParseResponseB64(
		r.Form.Get("SAMLResponse"),
		authnReqID, // Match the ID of our authentication request for increased security.
	)

	// Clear the ID of the outgoing Authnreq, regardless of the result.
	authnReqID = ""

	// TODO: better error handling:
	// - authentication failure
	// - authentication cancelled by user
	// - temporary server error
	// - unavailable SPID level

	// In case of SSO failure, display an error page.
	if err != nil {
		fmt.Printf("Bad Assertion received: %s\n", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Log response as required by the SPID rules.
	// Hint: log it in a way that does not mangle whitespace preventing signature from
	// being verified at a later time
	fmt.Printf("SPID Response: %s\n", response.XML)

	if response.Success() {
		// Login successful! Initialize our application session and store
		// the SPID information for later retrieval.
		// TODO: this should be stored in a database instead of the current Dancer
		// session, and it should be indexed by SPID SessionID so that we can delete
		// it when we get a LogoutRequest from an IdP.
		spidSession = response.Session()

		// TODO: handle SPID level upgrade:
		// - does session ID remain the same? better assume it changes

		http.Redirect(w, r, "/", http.StatusSeeOther)
	} else {
		fmt.Fprintf(w, "Authentication Failed: %s (%s)",
			response.StatusMessage(), response.StatusCode2())
	}
}
