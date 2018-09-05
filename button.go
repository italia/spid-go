package spid

import (
    "bytes"
    "fmt"
    "net/url"
    "html/template"
)

const tmpl_button = `
{{ range $entityID, $url := . }}
<p><a class="btn btn-primary" href="{{ $url }}">Login with SPID</a> <small>({{ $entityID }})</small></p>
{{ end }}
`

func (sp *SP) GetButton(pattern string) string {
    items := make(map[string]string)  // entityID: URL
    
    for entityID := range sp.IdP {
        items[entityID] = fmt.Sprintf(pattern, url.QueryEscape(entityID))
    }
    
    t := template.Must(template.New("button").Parse(tmpl_button))
    var button bytes.Buffer
    t.Execute(&button, items)
    return button.String()
}
