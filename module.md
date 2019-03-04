# Module cors-filter

Cross-Origin Resource Sharing.

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

**NOTICE**

Copyright 2019 Santos Zatarain Vera (coder.santoszv_at_gmail.com). This
product includes coded software by Santos Zatarain Vera and licensed under the
Apache License, Version 2.0 (https://github.com/santoszv/cors-filter).

Copyright (C) 2015 W3C (R) (MIT, ERCIM, Keio, Beihang). This software or
document includes material copied from or derived from Cross-Origin
Resource Sharing W3C Recommendation (https://www.w3.org/TR/cors/).