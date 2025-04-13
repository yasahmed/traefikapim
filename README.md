

# TraefikAPIM Plugin

## Overview


this document explain how to configure the `traefikapim` plugin in a `docker-compose.yml` file
## Features

- **Endpoint Security**: Supports multiple security mechanisms:
  - OAuth2
  - Static Header
  - JWT (planned, not yet implemented)
- **Request Transformations**: Modify request body or URI path using values from:
  - Headers
  - Request body
  - Query parameters
  - JWT token Claims (from `Authorization` header)
- **Header Management**:
  - Add new headers to requests
  - Remove specified headers from requests
- **IP Whitelisting**: Restrict access to specified IP addresses.

## Configuration

The plugin configuration is divided into two parts: **Global Configuration** (applied to all applications) and **Application-Specific Configuration** (unique to each internal application).

### Global Configuration

The global configuration defines settings that apply across all applications. Key configuration options include:

- **`jwtJks`** (`string`): URL to download the public key certificate for OAuth2 token validation.
  - Example: 
    ```yaml
    traefik.http.middlewares.uppercaseMiddleware.plugin.traefikapim.global.jwtJks=http://localhost:8080/realms/external/protocol/openid-connect/certs
    ```

- **`tokenUrl`** (`string`): OAuth2 token endpoint URL for client credential flow.
  - Example: 
    ```yaml
    traefik.http.middlewares.uppercaseMiddleware.plugin.traefikapim.global.tokenUrl=http://localhost:8080/realms/internal/protocol/openid-connect/token
    ```
- **`secret`** (`string`): Secret for OAuth2 client credential flow.
  - Example: 
    ```yaml
    "traefik.http.middlewares.uppercaseMiddleware.plugin.traefikapim.global.secret=oauth2 credential secret"
    ```
- **`clientId`** (`string`): Client ID for OAuth2 client credential flow.
  - Example:
    ```yaml
    traefik.http.middlewares.uppercaseMiddleware.plugin.traefikapim.global.clientId=your-client-id
    ```
  - **Note**: This version does not support token caching for performance optimization.

- **`secureHeaderName`** (`string`): Name of the static header used for applications secured by a static header for example (X-API-Key).
  - Example:
    ```yaml
    traefik.http.middlewares.uppercaseMiddleware.plugin.traefikapim.global.secureHeaderName=X-API-Key
    ```

### Application-Specific Configuration
You can configure multipple applications for each client service.
Each internal application has its own configuration, identified by :

- **`id`** (`string`): Unique identifier for the application.
- **`secureHeaderName`** (`string`): Header name for static security type (used in auth checks).
- **`secureHeaderValue`** (`string`): Header value for static security type (used in auth checks).
- **`enable`** (`boolean`): Enable or disable the application.
- **`sendOauth2AuthHeader`** (`boolean`): If enabled, the plugin will automatically:
  - Fetch a JWT token using the clientId, secret, and tokenUrl from the global configuration.
  - Inject this token into the Authorization header of every outgoing request.
- **`secured`** (`boolean`): Indicates if the application requires security.
  - `Oauth2`
  - `Jwt` (not yet implemented)
  - `Static`
- **`allowedIps`** (`array`): List of whitelisted IPs (e.g., `::1` for localhost).
- **`urls`** (`array`): List of endpoint configurations, each containing:
  - **`url`** (`string`): URI path for the endpoint.
  - **`method`** (`string`): HTTP method (e.g., GET, POST).
  - **`jspathRequest`** (`string`): JSONPath expression for transforming the request body.
  - **`JsPathVarable`** (`string`): JSONPath expression for transforming the URI path.
  - **`addHeaders`** (`array`): List of headers to add to the native service request.
  - **`removeHeaders`** (`array`): List of headers to remove from the native service request.

#### Example Application Configuration

```yaml
"traefik.http.middlewares.uppercaseMiddleware.plugin.traefikapim.applications[0].id=appLower"
"traefik.http.middlewares.uppercaseMiddleware.plugin.traefikapim.applications[0].enable=true"
"traefik.http.middlewares.uppercaseMiddleware.plugin.traefikapim.applications[0].securityType=OAUTH2"
"traefik.http.middlewares.uppercaseMiddleware.plugin.traefikapim.applications[0].allowedIps=::1,192.168.148.1"
"traefik.http.middlewares.uppercaseMiddleware.plugin.traefikapim.applications[0].secured=true"
"traefik.http.middlewares.uppercaseMiddleware.plugin.traefikapim.applications[0].urls[0].url=/api/lower"
"traefik.http.middlewares.uppercaseMiddleware.plugin.traefikapim.applications[0].urls[0].method=GET"
"traefik.http.middlewares.uppercaseMiddleware.plugin.traefikapim.applications[0].urls[0].jspathRequest={\"usrXXXX\": \"$$.info.toto\",\"claim\":\"_$$c.jti\",\"User-Agent5\": \"_$$h.boolvar\", \"User-Agent6\": \"_$$q.longvar\"}"
"traefik.http.middlewares.uppercaseMiddleware.plugin.traefikapim.applications[0].urls[0].JsPathVarable=/api/hola/$.size/$.page?jj=_$h.ahmed"
"traefik.http.middlewares.uppercaseMiddleware.plugin.traefikapim.applications[0].urls[0].addHeaders.X-Custom-Header=TOTO 1"
"traefik.http.middlewares.uppercaseMiddleware.plugin.traefikapim.applications[0].urls[0].addHeaders.User-Agent=TOTO M6"
"traefik.http.middlewares.uppercaseMiddleware.plugin.traefikapim.applications[0].urls[0].addHeaders.User-Agent2=ooo"
"traefik.http.middlewares.uppercaseMiddleware.plugin.traefikapim.applications[0].urls[0].addHeaders.User-Agent3=_$$c.jti"
"traefik.http.middlewares.uppercaseMiddleware.plugin.traefikapim.applications[0].urls[0].addHeaders.User-Agent4=_$$c.jti"
"traefik.http.middlewares.uppercaseMiddleware.plugin.traefikapim.applications[0].urls[0].addHeaders.User-Agent5=_$$c.boolvar"
"traefik.http.middlewares.uppercaseMiddleware.plugin.traefikapim.applications[0].urls[0].addHeaders.User-Agent6=_$$c.longvar"
"traefik.http.middlewares.uppercaseMiddleware.plugin.traefikapim.applications[0].urls[0].removeHeaders[0]=Ahmed"
```

The provided YAML configuration snippet is for the `traefikapim` Traefik plugin, specifically configuring a middleware named `uppercaseMiddleware`. It defines settings for a single application (the first in the `applications` array, indexed as `[0]`) and one endpoint (the first in the `urls` array, indexed as `[0]`). Below, I’ll explain each line in detail, breaking down what it does based on the plugin’s functionality you described earlier.

---

### Configuration Breakdown

The configuration is structured under the middleware path `traefik.http.middlewares.uppercaseMiddleware.plugin.traefikapim`. The plugin allows defining global settings and per-application settings. This snippet focuses on the first application (`applications[0]`) and its first endpoint (`urls[0]`).

#### 1. Application ID
```yaml
traefik.http.middlewares.uppercaseMiddleware.plugin.traefikapim.applications[0].id=appLower
```
- **Explanation**: Sets the unique identifier for the application to `appLower`. This ID distinguishes the application within the plugin’s configuration, allowing the plugin to apply specific settings to requests associated with this application.

---

#### 2. Enable Application
```yaml
traefik.http.middlewares.uppercaseMiddleware.plugin.traefikapim.applications[0].enable=true
```
- **Explanation**: Enables the application, meaning the plugin will process requests for this application. If set to `false`, the plugin would ignore this application’s configuration.

---

#### 3. Security Type
```yaml
traefik.http.middlewares.uppercaseMiddleware.plugin.traefikapim.applications[0].securityType=OAUTH2
```
- **Explanation**: Specifies that the application uses OAuth2 for security. The plugin will validate incoming requests using OAuth2 tokens. Based on your earlier description, this likely involves validating tokens against a public key certificate downloaded from a URL specified in the global configuration (e.g., `jwtJks`).

---

#### 4. Allowed IPs
```yaml
traefik.http.middlewares.uppercaseMiddleware.plugin.traefikapim.applications[0].allowedIps=::1,192.168.148.1
```
- **Explanation**: Defines the whitelisted IP addresses allowed to access this application. The list includes:
  - `::1`: IPv6 localhost (equivalent to `127.0.0.1` in IPv4).
  - `192.168.148.1`: A specific IP address, likely within a private network (e.g., a server or gateway in the LAN).
  The plugin will reject requests from IPs not in this list.

---

#### 5. Secured Flag
```yaml
traefik.http.middlewares.uppercaseMiddleware.plugin.traefikapim.applications[0].secured=true
```
- **Explanation**: Indicates that the application requires security checks. Since `securityType` is `OAUTH2`, the plugin will enforce OAuth2 token validation for all requests to this application’s endpoints.

---

#### 6. Endpoint URL
```yaml
traefik.http.middlewares.uppercaseMiddleware.plugin.traefikapim.applications[0].urls[0].url=/api/lower
```
- **Explanation**: Defines the URI path for the first endpoint as `/api/lower`. The plugin will apply the following configurations to requests matching this path.

---

#### 7. Endpoint Method
```yaml
traefik.http.middlewares.uppercaseMiddleware.plugin.traefikapim.applications[0].urls[0].method=GET
```
- **Explanation**: Specifies that the endpoint `/api/lower` handles `GET` requests. The plugin will only apply this configuration to `GET` requests to `/api/lower`.

---

#### 8. Request Body Transformation
```yaml
traefik.http.middlewares.uppercaseMiddleware.plugin.traefikapim.applications[0].urls[0].jspathRequest={"usrXXXX": "$$.info.toto","claim":"_$$c.jti","User-Agent5": "_$$c.boolvar", "User-Agent6": "_$$c.longvar"}
```
- **Explanation**: Configures a transformation of the request body using JSONPath expressions. The transformation creates or modifies the request body as a JSON object with the following key-value pairs:
  - `"usrXXXX": "$$.info.toto"`: Sets the `usrXXXX` field by a value extracted from the request body using JsonPath `$.info.toto` (prtefixed by **$.FIELD_NAME**).
  - `"claim": "_$$c.jti"`: Sets the `claim` field by a value extracted from jwt oauth token claims  using JsonPath `_$$c.jti` (prtefixed by **_$c.EMAIL**).
  - `"User-Agent5": "_$$h.boolvar"`: Sets the `User-Agent5` field by a value extracted from request header `boolvar` (prtefixed by **_$h.HEDAER1**).
  - `"User-Agent6": "_$$h.longvar"`: Sets the `User-Agent6` field by a value extracted from request query parameters `longvar` (prtefixed by **_$h.QUERY1**).

---

#### 9. URI Path Transformation
```yaml
traefik.http.middlewares.uppercaseMiddleware.plugin.traefikapim.applications[0].urls[0].JsPathVarable=/api/hola/$.size/$.page?jj=_$h.ahmed
```
- **Explanation**: Defines a transformation for the request’s URI path or query parameters using JSONPath:
  - The new URI path is constructed as `/api/hola/<size>/<page>?jj=<ahmed>`.
  - `$.size`: Extracts the `size` field from request body
  - `$.page`: Extracts the `page` field from request body
  - `jj=_$h.ahmed`: Sets the query parameter `jj` to the value of the `ahmed` header (`_$h` likely indicates a header source).
- **Purpose**: This rewrites the request URI dynamically, allowing the plugin to redirect or modify the target endpoint based on request data.

---

#### 10. Add Headers
```yaml
traefik.http.middlewares.uppercaseMiddleware.plugin.traefikapim.applications[0].urls[0].addHeaders.X-Custom-Header=TOTO 1
traefik.http.middlewares.uppercaseMiddleware.plugin.traefikapim.applications[0].urls[0].addHeaders.User-Agent2=ooo
traefik.http.middlewares.uppercaseMiddleware.plugin.traefikapim.applications[0].urls[0].addHeaders.User-Agent3=_$$c.claim1
traefik.http.middlewares.uppercaseMiddleware.plugin.traefikapim.applications[0].urls[0].addHeaders.User-Agent4=_$$h.header1
traefik.http.middlewares.uppercaseMiddleware.plugin.traefikapim.applications[0].urls[0].addHeaders.User-Agent5=_$$q.query1
```
- **Explanation**: Adds headers to the outgoing request:
  - `X-Custom-Header: TOTO 1`: Static header with value `TOTO 1`.
  - `User-Agent2: ooo`: Adds a custom header `User-Agent2` with a static value `ooo`.
  - `User-Agent3: _$$c.claim1`: Sets `User-Agent3` from the JWT’s `claim1` claim.
  - `User-Agent4: _$$h.header1`: Sets `User-Agent4` to the `header1` request header
  - `User-Agent5: _$$c.query1`: Sets `User-Agent5` to the `query1` body requezst query parameters
- **Note**: The repeated use of `User-Agent*` headers and `_$$c` placeholders suggests the plugin is designed to inject token claims into multiple headers, possibly for compatibility with downstream services.

---

#### 11. Remove Headers
```yaml
traefik.http.middlewares.uppercaseMiddleware.plugin.traefikapim.applications[0].urls[0].removeHeaders[0]=Ahmed
```
- **Explanation**: Removes the `Ahmed` header from the outgoing request. This ensures that the specified header is not forwarded to the downstream service, which might be useful for security or compatibility.

---

## Install

**Install the Plugin (in treafik docker-compose file)**: 
```yaml
      - "--experimental.localPlugins.traefikapim.moduleName=github.com/yasahmed/traefikapim"
```
- **`github.com/yasahmed/traefikapim`**  github.com/yasahmed/traefikapim depends on its repository path and location in the Traefik container's localPlugins directory. you can modify these by rebuilding the Traefik Docker image with your desired paths

## Limitations

- JWT security is not yet implemented.
- Token caching for OAuth2 client credential flow is not supported in this version.
- Public Key for Oauth2 token caching is not yet implemented to enhance performance.
- No conditional using JsonPath
