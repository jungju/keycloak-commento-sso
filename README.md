# Commento-Keycloak

## Flow
1. Server: Verify the HMAC
2. Server: Redirect to login page with token
3. Login Page: Keycloak Init
4. Keycloak: Login and redirect to login page
5. Login Page: Get user info from keycloak SDK and pass to the server
6. Server: Encode payload and redirect to commento

## pseudo-code of commento
https://docs.commento.io/configuration/frontend/sso.html
```
secret-key = hex-decode("001ac5d3c197c4d7493f561f5a696c149b925a07d8bedcee993745f15eb53ac6")

def handle-GET:
  token = query-param("token")
  hmac = hex-decode(query-param("hmac"))

  expected-hmac = hmac-sha256(hex-decode(token), secret-key)
  if hmac != expected-hmac:
    discard and terminate

  email, name, link, photo = authenticate()

  payload-json = {
    "token": token,
    "email": email,
    "name":  name,
    "link":  link,
    "photo": photo,
  }

  hmac = hex-encode(hmac-sha256(payload-json, secret-key))
  payload-hex = hex-encode(payload-json)

  302-redirect("https://commento.io/api/oauth/sso/callback?payload=" + payload-hex + "&hmac=" + hmac)
  ```

## Config

### KEYCLOAK_URL
- Keycloak URL
- https://keycloak

### KEYCLOAK_REALM
- Keycloak Realm

### KEYCLOAK_CLIENT_ID
- Keycloak Client id

### SECRET_KEY
- HMAC secret key

### COMMENTO_URL
- commento url
- https://my-commento.com

## Docker
```
docker run my/commento-keycloak
 -e KEYCLOAK_URL=https://keycloak \
 -e KEYCLOAK_REALM=myrealm \
 -e KEYCLOAK_CLIENT_ID=commento-keycloak \
 -e SECRET_KEY=hmacsecrekey1234 \
 -e COMMENTO_URL=https://my-commento.com \
```