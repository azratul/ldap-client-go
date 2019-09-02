# ldap-client-go

LDAP client to connect and retrieve information for a user.

Doesn't support TLS

# Usage

```golang
package main

import (
    "github.com/azratul/ldap-client-go"
)

func main() {
    client := &ldap.Client{
        BaseDN:             "dc=subdomain,dc=domain,dc=cl",
        Host:               "subdomain.domain.cl",
        Port:               389,
        BindUser:           "cn=admin,cn=Users",
        BindPass:           "password",
        SkipTLS:            true,
    }

    defer client.Close()

    client.Connect()

    client.Search("(&(sAMAccountName=USER))", []string{"dn", "cn", "givenName", "distinguishedName", "name", "userPrincipalName"})
}
```
