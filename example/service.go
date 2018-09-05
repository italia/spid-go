package main

import (
    "fmt"
    "io"
    "net/http"
    "github.com/italia/spid-go"
    "html/template"
)

// This demo application shows how to use the spid package

var sp spid.SP
var spidSession *spid.Session

func main() {
    // Initialize our SPID object with information about this Service Provider
    sp = spid.SP{
        EntityID:   "https://www.prova.it/",
        KeyFile:    "sp.key",
        CertFile:   "sp.pem",
        AssertionConsumerServices: []string{
            "http://localhost:3000/spid-sso",
        },
        SingleLogoutServices: map[string]spid.SAMLBinding{
            "http://localhost:3000/spid-slo": spid.HTTPRedirect,
        },
        AttributeConsumingServices: []spid.AttributeConsumingService{
            {
                ServiceName: "Service 1",
                Attributes: []string{"fiscalNumber", "name", "familyName", "dateOfBirth"},
            },
        },
    }
    
    // Load Identity Providers from their XML metadata
    err := sp.LoadIDPMetadata("idp_metadata")
    if (err != nil) {
        fmt.Print("Failed to load IdP metadata: ")
        fmt.Println(err)
        return
    }
    
    // Wire routes and endpoints of our example application
    http.HandleFunc("/", index)
    http.HandleFunc("/metadata", metadata)
    
    // Dance
    fmt.Println("spid-go example application listening on http://localhost:8000")
    http.ListenAndServe(":8000", nil)
}

const tmpl_layout = `<!DOCTYPE html>
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
        t := template.Must(template.New("index").Parse(tmpl_layout))
        t.Execute(w, template.HTML(button))
    } else {
        
    }
}

// This endpoint exposes our metadata
func metadata(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/xml")
    io.WriteString(w, sp.Metadata())
}
