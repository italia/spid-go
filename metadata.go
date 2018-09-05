package spid

import (
    "bytes"
    "encoding/xml"
    "io/ioutil"
    "log"
    "os"
    "github.com/crewjam/saml"
    "path/filepath"
    "text/template"
)
 
func (sp *SP) LoadIDPFromXMLFile(path string) error {
    // open XML file
    xmlFile, err := os.Open(path)
    if err != nil {
        return err
    }
    defer xmlFile.Close()
    
    // read our opened xmlFile as a byte array.
    byteValue, _ := ioutil.ReadAll(xmlFile)
    
    // parse the XML file
    var entity saml.EntityDescriptor
    err = xml.Unmarshal(byteValue, &entity)
    if err != nil {
        return err
    }
    
    // store the loaded IdP
    if (sp.IdP == nil) {
        sp.IdP = make(map[string]*saml.EntityDescriptor)
    }
    sp.IdP[entity.EntityID] = &entity
    
    return nil
}

func (sp *SP) LoadIDPMetadata(dir string) error {
    files, err := filepath.Glob(dir + "/*.xml")
    if (err != nil) {
        log.Fatal(err)
    }
    
    for _, file := range files {
        err := sp.LoadIDPFromXMLFile(file)
        if err != nil {
            return err
        }
    }
    
    return nil
}

func (sp *SP) Metadata() string {
    sp.LoadCert()
    
    const tmpl = `<?xml version="1.0"?> 
<md:EntityDescriptor 
    xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"  
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#"  
    entityID="{{.EntityID}}"  
    ID="_681a637-6cd4-434f-92c3-4fed720b2ad8"> 
     
    <md:SPSSODescriptor  
        protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"  
        AuthnRequestsSigned="true"  
        WantAssertionsSigned="true"> 
        
        <md:KeyDescriptor use="signing"> 
            <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"> 
                <ds:X509Data> 
                    <ds:X509Certificate>{{ .Cert }}</ds:X509Certificate> 
                </ds:X509Data> 
            </ds:KeyInfo> 
        </md:KeyDescriptor>
        
        {{ range $url, $binding := .SingleLogoutServices }}
        <md:SingleLogoutService 
            Binding="{{ $binding }}"
            Location="{{ $url }}" /> 
        {{ end }}
        
        <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat> 

        {{ range $index, $url := .AssertionConsumerServices }}
        <md:AssertionConsumerService  
            Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"  
            Location="{{ $url }}"  
            index="{{ $index }}"  
            isDefault="{{ if $index }}false{{ else }}true{{ end }}" /> 
        {{ end }}
        
        {{ range $index, $attcs := .AttributeConsumingServices }}
        <md:AttributeConsumingService index="{{ $index }}"> 
            <md:ServiceName xml:lang="it">{{ $attcs.ServiceName }}</md:ServiceName>
            {{ range $attr := $attcs.Attributes }}
            <md:RequestedAttribute Name="{{ $attr }}" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/> 
            {{ end }}
        </md:AttributeConsumingService>
        {{ end }}

    </md:SPSSODescriptor> 

</md:EntityDescriptor>
`
    t := template.Must(template.New("metadata").Parse(tmpl))
    var metadata bytes.Buffer
    t.Execute(&metadata, sp)
    
    return metadata.String()
}