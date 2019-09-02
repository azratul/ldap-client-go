package ldap

import (
    "fmt"
    "crypto/tls"
    "gopkg.in/ldap.v3"
)

type Client struct {
    Conn               *ldap.Conn
    BaseDN             string
    BindUser           string
    BindPass           string
    ServerName         string
    Host               string
    Port               int
    SkipTLS            bool
}

func (client *Client) Connect() error {
    if client.Conn == nil {
        var l *ldap.Conn
        var err error
        address := fmt.Sprintf("%s:%d", client.Host, client.Port)

        l, err = ldap.Dial("tcp", address)
        if err != nil {
            return err
        }

        if !client.SkipTLS {
            err = l.StartTLS(&tls.Config{InsecureSkipVerify: true})
            if err != nil {
                return err
            }
        }

        if client.BindUser != "" && client.BindPass != "" {
            err := l.Bind(fmt.Sprintf("%s,%s", client.BindUser, client.BaseDN), client.BindPass)
            if err != nil {
                return nil
            }
        }

        client.Conn = l
    }

    return nil
}

func (client *Client) Search(filter string, attr []string) error {
    searchRequest := ldap.NewSearchRequest(
        client.BaseDN,
        ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
        filter,
        attr,
        nil,
    )

    sr, err := client.Conn.Search(searchRequest)
    if err != nil {
        return err
    }

    for _, entry := range sr.Entries {
        fmt.Printf(
            "%s: %v\n", entry.DN,
            entry.GetAttributeValue("cn"),
            entry.GetAttributeValue("givenName"),
            entry.GetAttributeValue("distinguishedName"),
            entry.GetAttributeValue("name"),
            entry.GetAttributeValue("userPrincipalName"),
        )
    }

    return nil
}

func (client *Client) Close() {
    if client.Conn != nil {
        client.Conn.Close()
        client.Conn = nil
    }
}