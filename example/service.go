package main

import (
    "fmt"
    "io"
    "net/http"
    "github.com/italia/spid-go"
)

// This demo application shows how to use the spid package

var sp spid.SP
var spidSession spid.Session

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
    err := sp.LoadIDPFromXMLFile("idp_metadata/spid-testenv2.xml")
    if (err != nil) {
        fmt.Print("Failed to load IdP metadata: ")
        fmt.Println(err)
        return
    }
    
    // Wire routes and endpoints of our example application
    http.HandleFunc("/metadata", metadata)
    
    // Dance
    fmt.Println("spid-go example application listening on http://localhost:8000")
    http.ListenAndServe(":8000", nil)
}

// This endpoint exposes our metadata
func metadata(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/xml")
    io.WriteString(w, sp.Metadata())
}
