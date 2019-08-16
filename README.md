# Cross-Origin Resource Sharing (CORS) Web Filter

User agents commonly apply same-origin restrictions to network requests. These
restrictions prevent a client-side Web application running from one origin from
obtaining data retrieved from another origin, and also limit unsafe HTTP
requests that can be automatically launched toward destinations that differ
from the running application's origin.

In user agents that follow this pattern, network requests typically include
user credentials with cross-origin requests, including HTTP authentication and
cookie information.

This specification extends this model in several ways:

- A response can include an Access-Control-Allow-Origin header, with the origin
  of where the request originated from as the value, to allow access to the
  resource's contents.

  The user agent validates that the value and origin of where the request
  originated match.

- User agents can discover via a preflight request whether a cross-origin
  resource is prepared to accept requests, using a non-simple method, from a
  given origin.

  This is again validated by the user agent.

- Server-side applications are enabled to discover that an HTTP request was
  deemed a cross-origin request by the user agent, through the Origin header.

  This extension enables server-side applications to enforce limitations (e.g.
  returning nothing) on the cross-origin requests that they are willing to
  service.

## Usage in Gradle (Kotlin)

1. Add Maven Central repository

    ```
    repositories {
        mavenCentral()
    }
    ```

2. Add dependencies

    ```
    dependencies {
        implementation("mx.com.inftel.oss:cors-filter:1.2.0")
    }
    ```

3. Create a CORS policies file in classpath

    Full CORS policies file:

    ```
    <?xml version="1.0" encoding="UTF-8"?>
    <cors-policies>
        <origins>
            <origin>http://frontend.domain.com</origin>
            <origin>https://frontend.domain.com</origin>
            <origin>http://frontend.domain.com:8080</origin>
            <origin>https://frontend.domain.com:8443</origin>
        </origins>
        <methods>
            <method>HEAD</method>
            <method>GET</method>
            <method>POST</method>
            <method>PUT</method>
            <method>DELETE</method>
        </methods>
        <headers>
            <header>Authorization</header>
            <header>X-Anti-CSRF</header>
            <header>X-Requested-With</header>
        </headers>
        <exposed-headers>
            <header>Content-Length</header>
            <header>WWW-Authenticate</header>
            <header>Server-Authenticate</header>
            <header>X-Anti-CSRF</header>
        </exposed-headers>
        <supports-credentials>false</supports-credentials>
        <access-control-max-age>-1</access-control-max-age>
        <preflight-continue-chain>false</preflight-continue-chain>
        <preflight-prefer-no-content>false</preflight-prefer-no-content>
    </cors-policies>
    ```

    Recommended minimal CORS policies file:

    ```
    <?xml version="1.0" encoding="UTF-8"?>
    <cors-policies>
        <headers>
            <header>Authorization</header>
        </headers>
        <exposed-headers>
            <header>Content-Length</header>
            <header>WWW-Authenticate</header>
            <header>Server-Authenticate</header>
        </exposed-headers>
    </cors-policies>
    ```

4. Add filter to web.xml

    Example of filter using CORS policies file named cors-policies.xml at root
    package:

    ```
    <filter>
        <filter-name>CORS</filter-name>
        <filter-class>mx.com.inftel.cors.CORSServletFilter</filter-class>
        <init-param>
            <param-name>cors-policies</param-name>
            <param-value>cors-policies.xml</param-value>
        </init-param>
    </filter>
    ```

5. Map filter to desired locations

    ```
    <filter-mapping>
        <filter-name>CORS</filter-name>
        <url-pattern>/api/*</url-pattern>
        <dispatcher>REQUEST</dispatcher>
    </filter-mapping>
    ```

## License

Copyright 2019 Santos Zatarain Vera <coder.santoszv(at)gmail.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

## Notice

Copyright 2019 Santos Zatarain Vera (coder.santoszv_at_gmail.com). This
product includes coded software by Santos Zatarain Vera and licensed under the
Apache License, Version 2.0 (https://github.com/santoszv/cors-filter).

Copyright (C) 2015 W3C (R) (MIT, ERCIM, Keio, Beihang). This software or
document includes material copied from or derived from Cross-Origin
Resource Sharing W3C Recommendation (https://www.w3.org/TR/cors/).