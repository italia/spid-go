package spidsaml

import (
	"bytes"
	"fmt"
	"html/template"
	"net/url"
)

const tmplButton = `
{{ range $entityID, $url := . }}
<p><a class="btn btn-primary" href="{{ $url }}">Login with SPID</a> <small>({{ $entityID }})</small></p>
{{ end }}
`

// GetButton returns the rendered HTML of the SPID button.
func (sp *SP) GetButton(pattern string) string {
	items := make(map[string]string) // entityID: URL

	for entityID := range sp.IDP {
		items[entityID] = fmt.Sprintf(pattern, url.QueryEscape(entityID))
	}

	t := template.Must(template.New("button").Parse(tmplButton))
	var button bytes.Buffer
	t.Execute(&button, items)
	return button.String()
}
