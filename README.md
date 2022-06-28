# OAuth
---

> OAuth2.0 for Golang webservices with persistent sessions with TTL
---

#### Basic Authentication
- For use with BasicAuthentication, use the username `u` in your request.
- base64encode `encoded = btoa("u:yourtoken")`
- Sample request header: `Authorization:Basic encoded`