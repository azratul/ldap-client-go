package ldap

import (
    "crypto/tls"
    "crypto/x509"
    "errors"
    "io/ioutil"
    "log"
    "strconv"
    "strings"
    "time"

    "golang.org/x/text/encoding/unicode"
    "gopkg.in/ldap.v3"
)

// Client : Estructura básica necesaria
// para para conectarse a Active Directory
type Client struct {
    Conn               *ldap.Conn
    BaseDN             string
    BindUser           string
    Group              string
    BindPass           string
    ServerName         string
    Host               string
    Port               int
    InsecureSkipVerify bool
    UseTLS             bool
    SkipTLS            bool
    FileCert           string
}

// Person : Estructura de retorno con la
// información de la persona desde Active Directory
type User struct {
    Dn                 string
    Cn                 string
    Sn                 string
    Group              string
    GivenName          string
    DistinguishedName  string
    InstanceType       string
    WhenCreated        string
    WhenChanged        string
    DisplayName        string
    USNCreated         string
    USNChanged         string
    Name               string
    ObjectGUID         string
    UserAccountControl string
    LastLogoff         string
    LastLogon          string
    PrimaryGroupID     string
    ObjectSid          string
    AccountExpires     string
    LogonCount         string
    SAMAccountName     string
    ObjectClass        string
    SAMAccountType     string
    UserPrincipalName  string
    UserPassword       string
    UnicodePwd         string
}

const (
    Exists     = "EXISTS"
    NotFound   = "NOT_FOUND"
    Error      = "ERROR"
    Successful = "Successful"
)

// Connect : función que efectúa la conexión a Active Directory,
// debe recibir una estructura tipo Client
func (client *Client) Connect() error {
    if client == nil {
        return errors.New("No se ha inicializado la conexión")
    }

    if client.Conn == nil {
        var l *ldap.Conn
        var err error
        address := client.Host+":"+strconv.Itoa(client.Port)

        if !client.UseTLS {
            l, err = ldap.Dial("tcp", address)
            if err != nil {
                return err
            }

            // Reconnect with TLS
            if !client.SkipTLS {
                err = l.StartTLS(&tls.Config{InsecureSkipVerify: true})
                if err != nil {
                    return err
                }
            }
        } else {
            rootCA, err := x509.SystemCertPool()
            if err != nil {
                return errors.New("Failed to load system cert: "+err.Error())
            }
            if rootCA == nil {
                log.Printf("root ca is nil")
                rootCA = x509.NewCertPool()
            }

            ldapCert, err := ioutil.ReadFile("./certs/"+client.FileCert+".cer")
            if err != nil {
                return errors.New("Failed to read ad cert: "+err.Error())
            }
            ok := rootCA.AppendCertsFromPEM(ldapCert)
            if !ok {
                return errors.New("AD cert of "+client.FileCert+" is not addeded.")
            }

            config := &tls.Config{
                InsecureSkipVerify: client.InsecureSkipVerify,
                ServerName:         client.ServerName,
                RootCAs:            rootCA,
            }
            l, err = ldap.DialTLS("tcp", address, config)
            if err != nil {
                return err
            }
        }

        if client.BindUser != "" && client.BindPass != "" {
            err := l.Bind("CN="+client.BindUser+",CN="+client.Group+","+client.BaseDN, client.BindPass)
            if err != nil {
                return err
            }
        }

        client.Conn = l
    }

    return nil
}

// Search : Función para buscar usuarios en Active Directory,
// filter se usa para filtrar a los usuarios y attr se usa para
// seleccionar los atributos. Mas información como usar filter en
// http://www.ldapexplorer.com/en/manual/109010000-ldap-filter-syntax.htm
func (client *Client) Search(filter string, attr []string) ([]User, error) {
    if err := client.Connect(); err != nil {
        return nil, err
    }
    defer client.Close()

    searchRequest := ldap.NewSearchRequest(
        client.BaseDN,
        ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
        filter,
        attr,
        nil,
    )

    sr, err := client.Conn.Search(searchRequest)
    if err != nil {
        return nil, err
    }

    var users []User
    for _, entry := range sr.Entries {
        a := User{
            Dn:                 entry.DN,
            Cn:                 entry.GetAttributeValue("cn"),
            Sn:                 entry.GetAttributeValue("sn"),
            GivenName:          entry.GetAttributeValue("givenName"),
            DistinguishedName:  entry.GetAttributeValue("distinguishedName"),
            InstanceType:       entry.GetAttributeValue("instanceType"),
            WhenCreated:        entry.GetAttributeValue("whenCreated"),
            WhenChanged:        entry.GetAttributeValue("whenChanged"),
            DisplayName:        entry.GetAttributeValue("displayName"),
            USNCreated:         entry.GetAttributeValue("uSNCreated"),
            USNChanged:         entry.GetAttributeValue("uSNChanged"),
            Name:               entry.GetAttributeValue("name"),
            ObjectGUID:         entry.GetAttributeValue("objectGUID"),
            UserAccountControl: entry.GetAttributeValue("userAccountControl"),
            LastLogoff:         entry.GetAttributeValue("lastLogoff"),
            LastLogon:          entry.GetAttributeValue("lastLogon"),
            PrimaryGroupID:     entry.GetAttributeValue("primaryGroupID"),
            ObjectSid:          entry.GetAttributeValue("objectSid"),
            AccountExpires:     entry.GetAttributeValue("accountExpires"),
            LogonCount:         entry.GetAttributeValue("logonCount"),
            SAMAccountName:     entry.GetAttributeValue("sAMAccountName"),
            SAMAccountType:     entry.GetAttributeValue("sAMAccountType"),
            UserPrincipalName:  entry.GetAttributeValue("userPrincipalName"),
        }

        users = append(users, a)
    }

    return users, nil
}

// Add : Función para crear una cuenta en Active Directory
func (client *Client) Add(user User) (string, error) {
    if user.Cn == "" && user.Group == "" {
        return Error, errors.New("CN y Group son atributos obligatorios")
    }

    if err := client.Connect(); err != nil {
        return Error, err
    }
    defer client.Close()

    userDn := "CN="+user.Cn+",CN="+user.Group+","+client.BaseDN

    if exist, err := client.exist("(&(distinguishedName=" + userDn + "))"); err != nil {
        return Error, err
    } else if exist {
        return Exists, nil
    }

    addRequest := ldap.NewAddRequest(userDn, nil)

    if user.ObjectClass != "" &&
        user.SAMAccountName != "" &&
        user.Cn != "" &&
        user.GivenName != "" &&
        user.DisplayName != "" &&
        user.UserPrincipalName != "" {

        addRequest.Attribute("objectClass", []string{user.ObjectClass})
        addRequest.Attribute("sAMAccountName", []string{user.SAMAccountName})
        addRequest.Attribute("cn", []string{user.Cn})
        addRequest.Attribute("givenName", []string{user.GivenName})
        addRequest.Attribute("displayName", []string{user.DisplayName})
        addRequest.Attribute("userPrincipalName", []string{user.UserPrincipalName})

        if user.UserPassword != "" {
            addRequest.Attribute("userPassword", []string{user.UserPassword})
        }

        if user.Sn != "" {
            addRequest.Attribute("sn", []string{user.Sn})
        }

        if user.AccountExpires != "" {
            addRequest.Attribute("accountExpires", []string{user.AccountExpires})
        }

        if user.DistinguishedName != "" {
            addRequest.Attribute("distinguishedName", []string{user.DistinguishedName})
        }

        if user.InstanceType != "" {
            addRequest.Attribute("instanceType", []string{user.InstanceType})
        }

        if user.Name != "" {
            addRequest.Attribute("name", []string{user.Name})
        }

        if user.UserAccountControl != "" {
            addRequest.Attribute("userAccountControl", []string{user.UserAccountControl})
        }

        if user.LastLogon != "" {
            addRequest.Attribute("lastLogon", []string{user.LastLogon})
        }

        if user.SAMAccountType != "" {
            addRequest.Attribute("sAMAccountType", []string{user.SAMAccountType})
        }

        if err := client.Conn.Add(addRequest); err != nil {
            return Error, errors.New("Agregar usuario falló" + err.Error())
        }
    } else {
        return Error, errors.New("Estas omitiendo atributos obligatorios")
    }

    return Successful, nil
}

// Update : Función para actualizar la información
// de un usuario en Active Directory
func (client *Client) Update(user User) (string, error) {
    if user.Cn == "" && user.Group == "" {
        return Error, errors.New("CN y Group son atributos obligatorios")
    }

    if err := client.Connect(); err != nil {
        return Error, err
    }
    defer client.Close()

    userDn := "CN="+user.Cn+",CN="+user.Group+","+client.BaseDN

    if exist, err := client.exist("(&(distinguishedName=" + userDn + "))"); err != nil {
        return Error, err
    } else if !exist {
        return NotFound, nil
    }

    mr := ldap.NewModifyRequest(userDn, nil)

    if user.GivenName != "" {
        mr.Replace("givenName", []string{user.GivenName})
    }

    if user.DisplayName != "" {
        mr.Replace("displayName", []string{user.DisplayName})
    }

    if user.UserPrincipalName != "" {
        mr.Replace("userPrincipalName", []string{user.UserPrincipalName})
    }

    if user.UnicodePwd != "" {
        utf16 := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM)
        pwdEncoded, _ := utf16.NewEncoder().String("\"" + user.UnicodePwd + "\"")
        mr.Replace("unicodePwd", []string{pwdEncoded})
    }

    if user.Sn != "" {
        mr.Replace("sn", []string{user.Sn})
    }

    if user.AccountExpires != "" {
        mr.Replace("accountExpires", []string{user.AccountExpires})
    }

    if user.DistinguishedName != "" {
        mr.Replace("distinguishedName", []string{user.DistinguishedName})
    }

    if user.InstanceType != "" {
        mr.Replace("instanceType", []string{user.InstanceType})
    }

    if user.Name != "" {
        mr.Replace("name", []string{user.Name})
    }

    if user.UserAccountControl != "" {
        mr.Replace("userAccountControl", []string{user.UserAccountControl})
    }

    if user.SAMAccountType != "" {
        mr.Replace("sAMAccountType", []string{user.SAMAccountType})
    }

    if err := client.Conn.Modify(mr); err != nil {
        return Error, errors.New("Se produjo un error al actualizar el usuario " + err.Error())
    }

    return Successful, nil
}

// Delete : Función para eliminar una cuenta en Active Directory
func (client *Client) Delete(user User) (string, error) {
    if user.Cn == "" && user.Group == "" {
        return Error, errors.New("CN y Group son atributos obligatorios")
    }

    if err := client.Connect(); err != nil {
        return Error, err
    }
    defer client.Close()

    userDn := "CN="+user.Cn+",CN="+user.Group+","+client.BaseDN

    exist, err := client.exist("(&(distinguishedName=" + userDn + "))")
    if err != nil {
        return Error, err
    }
    if !exist {
        return NotFound, nil
    }

    if err := client.Conn.Del(ldap.NewDelRequest(userDn, nil)); err != nil {
        return Error, errors.New("Se produjo un error al eliminar el usuario " + err.Error())
    }

    return Successful, nil
}

// Exist : Función para verificar si existe una cuenta en Active Directory
func (client *Client) exist(filterMSG string) (bool, error) {
    search := ldap.NewSearchRequest(
        client.BaseDN,
        ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
        filterMSG,
        []string{},
        nil)

    sr, err := client.Conn.Search(search)
    if err != nil {
        return false, err
    }

    if len(sr.Entries) != 0 {
        return true, nil
    }

    return false, nil
}

// LDAP TIME - Input ISO8601 Date, Return Windows NT time format
func GenerateExpirationTime(isoDate string) int64 {
    //year int, month time.Month, day int
    date := strings.Split(isoDate, "-")
    year, _ := strconv.Atoi(date[0])
    month, _ := strconv.Atoi(date[1])
    day, _ := strconv.Atoi(date[2])
    return (time.Date(year, time.Month(month), day, 23, 59, 59, 0, time.UTC).Unix() * 10000000) + 116444736000000000
}

func GenerateIsoDate(expirationTime int64) string {
    unixTime := (expirationTime - 116444736000000000) / 10000000
    tm := time.Unix(unixTime, 0)
    //fmt.Sprintf("%d-%02d-%d", tm.Year(), int(tm.Month()), tm.Day())
    isoDate := strconv.Itoa(tm.Year())+"-"+strconv.Itoa(int(tm.Month()))+"-"+strconv.Itoa(tm.Day())
    return isoDate
}

// Close : Función para cerrar una conexión al Active Directory
func (client *Client) Close() {
    if client.Conn != nil {
        client.Conn.Close()
        client.Conn = nil
    }
}
