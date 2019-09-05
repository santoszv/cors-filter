/*
 * Copyright 2019 Santos Zatarain Vera (coder.santoszv_at_gmail.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package mx.com.inftel.cors

import javax.servlet.*
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import javax.xml.bind.JAXB
import javax.xml.bind.annotation.*
import javax.xml.transform.stream.StreamSource

/**
 * Origin request header.
 *
 * Present in actual and preflight requests.
 */
const val REQ_HEADER_ORIGIN = "Origin"
/**
 * Access-Control-Request-Method request header.
 *
 * Present in just actual requests.
 */
const val REQ_HEADER_AC_REQUEST_METHOD = "Access-Control-Request-Method"
/**
 * Access-Control-Request-Headers request header.
 *
 * Present in just actual requests.
 */
const val REQ_HEADER_AC_REQUEST_HEADERS = "Access-Control-Request-Headers"

/**
 * Access-Control-Allow-Origin response header.
 *
 * Present in response to an actual request.
 */
const val RESP_HEADER_AC_ALLOW_ORIGIN = "Access-Control-Allow-Origin"
/**
 * Access-Control-Expose-Headers response header.
 *
 * Present in response to an actual request.
 */
const val RESP_HEADER_AC_EXPOSE_HEADERS = "Access-Control-Expose-Headers"
/**
 * Access-Control-Allow-Credentials response header.
 *
 * Present in response to an actual request or a preflight request.
 */
const val RESP_HEADER_AC_ALLOW_CREDENTIALS = "Access-Control-Allow-Credentials"
/**
 * Access-Control-Max-Age response header.
 *
 * Present in response to an preflight request.
 */
const val RESP_HEADER_AC_MAX_AGE = "Access-Control-Max-Age"
/**
 * Access-Control-Allow-Methods response header.
 *
 * Present in response to an preflight request.
 */
const val RESP_HEADER_AC_ALLOW_METHODS = "Access-Control-Allow-Methods"
/**
 * Access-Control-Allow-Headers response header.
 *
 * Present in response to an preflight request.
 */
const val RESP_HEADER_AC_ALLOW_HEADERS = "Access-Control-Allow-Headers"
/**
 * Vary response header.
 *
 * May be present in response to an actual request.
 */
const val RESP_HEADER_VARY = "Vary"

/**
 * Cross-Origin Resource Sharing (CORS) Web Filter.
 */
open class CORSServletFilter : AbstractCORSServletFilter() {

    override lateinit var policies: CORSPolicies

    /**
     * Init.
     *
     * Init parameter "cors-policies" is used for loading CORS policies from an
     * XML file in classpath. The init parameter value must comply with
     * [ClassLoader.getResourceAsStream] semantics.
     */
    override fun init(filterConfig: FilterConfig) {
        val policies = filterConfig.getInitParameter("cors-policies")
                ?: throw IllegalArgumentException("Init parameter 'cors-policies' is missing.")
        Thread.currentThread().contextClassLoader.getResourceAsStream(policies).use {
            this.policies = JAXB.unmarshal(StreamSource(it), CORSPoliciesElement::class.java)
        }
    }
}

/**
 * Cross-Origin Resource Sharing (CORS) Abstract Web Filter.
 */
abstract class AbstractCORSServletFilter : Filter {

    /**
     * Cross-Origin Resource Sharing (CORS) Policies
     */
    protected abstract val policies: CORSPolicies

    /**
     * Init.
     *
     * Currently this is a NO-OP.
     */
    override fun init(filterConfig: FilterConfig) {
        // NO-OP
    }

    /**
     * Filtering process.
     */
    override fun doFilter(request: ServletRequest, response: ServletResponse, chain: FilterChain) {
        val httpServletRequest = request as HttpServletRequest
        val httpServletResponse = response as HttpServletResponse
        when (httpServletRequest.method) {
            "OPTIONS" -> doFilterPreflight(httpServletRequest, httpServletResponse, chain)
            else -> doFilterActual(httpServletRequest, httpServletResponse, chain)
        }
    }

    /**
     * Process Actual Request.
     */
    private fun doFilterActual(request: HttpServletRequest, response: HttpServletResponse, chain: FilterChain) {
        // 1. If the Origin header is not present terminate this set of steps. The request is outside the scope of this
        //    specification.
        val originHeader = request.getHeader(REQ_HEADER_ORIGIN)
        if (originHeader == null) {
            chain.doFilter(request, response)
            return
        }
        // 2. If the value of the Origin header is not a case-sensitive match for any of the values in list of origins,
        //    do not set any additional headers and terminate this set of steps.
        //
        //    Note: Always matching is acceptable since the list of origins can be unbounded.
        if (policies.listOfOrigins.isNotEmpty()) {
            val match = policies.listOfOrigins.firstOrNull {
                it.equals(originHeader, false)
            }
            if (match == null) {
                chain.doFilter(request, response)
                return
            }
        }
        // 3. If the resource supports credentials add a single Access-Control-Allow-Origin header, with the value of
        //    the Origin header as value, and add a single Access-Control-Allow-Credentials header with the
        //    case-sensitive string "true" as value.
        //
        //    Otherwise, add a single Access-Control-Allow-Origin header, with either the value of the Origin header or
        //    the string "*" as value.
        //
        //    Note: The string "*" cannot be used for a resource that supports credentials.
        if (policies.supportsCredentials) {
            response.setHeader(RESP_HEADER_AC_ALLOW_ORIGIN, originHeader)
            response.setHeader(RESP_HEADER_AC_ALLOW_CREDENTIALS, "true")
            response.setHeader(RESP_HEADER_VARY, REQ_HEADER_ORIGIN)
        } else {
            response.setHeader(RESP_HEADER_AC_ALLOW_ORIGIN, "*")
        }
        // 4. If the list of exposed headers is not empty add one or more Access-Control-Expose-Headers headers, with as
        //    values the header field names given in the list of exposed headers.
        //
        //    Note: By not adding the appropriate headers resource can also clear the preflight result cache of all
        //    entries where origin is a case-sensitive match for the value of the Origin header and url is a
        //    case-sensitive match for the URL of the resource.
        if (policies.listOfExposedHeaders.isNotEmpty()) {
            response.setHeader(RESP_HEADER_AC_EXPOSE_HEADERS, policies.listOfExposedHeaders.joinToString(", "))
        }
        // Continue filter chain
        chain.doFilter(request, response)
    }

    /**
     * Process Preflight Request.
     */
    private fun doFilterPreflight(request: HttpServletRequest, response: HttpServletResponse, chain: FilterChain) {
        // 1. If the Origin header is not present terminate this set of steps. The request is outside the scope of this
        //    specification.
        val origin = request.getHeader(REQ_HEADER_ORIGIN)
        if (origin == null) {
            chain.doFilter(request, response)
            return
        }
        // 2. If the value of the Origin header is not a case-sensitive match for any of the values in list of origins
        //    do not set any additional headers and terminate this set of steps.
        //
        //    Note: Always matching is acceptable since the list of origins can be unbounded.
        //
        //    Note: The Origin header can only contain a single origin as the user agent will not follow redirects.
        if (policies.listOfOrigins.isNotEmpty()) {
            val match = policies.listOfOrigins.firstOrNull {
                it.equals(origin, false)
            }
            if (match == null) {
                chain.doFilter(request, response)
                return
            }
        }
        // 3. Let `method` be the value as result of parsing the Access-Control-Request-Method header.
        //
        //    If there is no Access-Control-Request-Method header or if parsing failed, do not set any additional
        //    headers and terminate this set of steps. The request is outside the scope of this specification.
        val method = request.getHeader(REQ_HEADER_AC_REQUEST_METHOD)
        if (method == null) {
            chain.doFilter(request, response)
            return
        }
        // 4. Let `header field-names` be the values as result of parsing the Access-Control-Request-Headers headers.
        //
        //    If there are no Access-Control-Request-Headers headers let `header field-names` be the empty list.
        //
        //    If parsing failed do not set any additional headers and terminate this set of steps. The request is
        //    outside the scope of this specification.
        val headerFieldNames = run {
            val header = request.getHeaders(REQ_HEADER_AC_REQUEST_HEADERS)
            if (header == null) {
                // Container does not allow access to header information, so, failed.
                chain.doFilter(request, response)
                return
            }
            header.asSequence()
                    .filterNotNull()
                    .map {
                        it.trim()
                    }
                    .filter {
                        it.isNotBlank()
                    }
                    .flatMap {
                        it.split(',').asSequence()
                    }
                    .map {
                        it.trim()
                    }
                    .filter {
                        it.isNotBlank()
                    }
                    .toList()
        }
        // 5. If `method` is not a case-sensitive match for any of the values in list of methods do not set any
        //    additional headers and terminate this set of steps.
        //
        //    Note: Always matching is acceptable since the list of methods can be unbounded.
        if (policies.listOfMethods.isNotEmpty()) {
            val match = policies.listOfMethods.firstOrNull {
                it.equals(method, false)
            }
            if (match == null) {
                chain.doFilter(request, response)
                return
            }
        }
        // 6. If any of the header field-names is not a ASCII case-insensitive match for any of the values in list of
        //    headers do not set any additional headers and terminate this set of steps.
        //
        //    Note: Always matching is acceptable since the list of headers can be unbounded.
        if (policies.listOfHeaders.isNotEmpty()) {
            headerFieldNames.forEach { headerFieldName ->
                val match = policies.listOfHeaders.firstOrNull {
                    it.equals(headerFieldName, true)
                }
                if (match == null) {
                    chain.doFilter(request, response)
                    return
                }
            }
        }
        // 7. If the resource supports credentials add a single Access-Control-Allow-Origin header, with the value of
        //    the Origin header as value, and add a single Access-Control-Allow-Credentials header with the
        //    case-sensitive string "true" as value.
        //
        //    Otherwise, add a single Access-Control-Allow-Origin header, with either the value of the Origin header or
        //    the string "*" as value.
        //
        //    Note: The string "*" cannot be used for a resource that supports credentials.
        if (policies.supportsCredentials) {
            response.setHeader(RESP_HEADER_AC_ALLOW_ORIGIN, origin)
            response.setHeader(RESP_HEADER_AC_ALLOW_CREDENTIALS, "true")
            response.setHeader(RESP_HEADER_VARY, REQ_HEADER_ORIGIN)
        } else {
            response.setHeader(RESP_HEADER_AC_ALLOW_ORIGIN, "*")
        }
        // 8. Optionally add a single Access-Control-Max-Age header with as value the amount of seconds the user agent
        //    is allowed to cache the result of the request.
        if (policies.accessControlMaxAge >= 0) {
            response.setHeader(RESP_HEADER_AC_MAX_AGE, "${policies.accessControlMaxAge}")
        }
        // 9. If method is a simple method this step may be skipped.
        //
        //    Add one or more Access-Control-Allow-Methods headers consisting of (a subset of) the list of methods.
        //
        //    Note: If a method is a simple method it does not need to be listed, but this is not prohibited.
        //
        //    Note: Since the list of methods can be unbounded, simply returning the method indicated by
        //          Access-Control-Request-Method (if supported) can be enough.
        if (policies.listOfMethods.isNotEmpty()) {
            response.setHeader(RESP_HEADER_AC_ALLOW_METHODS, policies.listOfMethods.joinToString(", "))
        } else {
            response.setHeader(RESP_HEADER_AC_ALLOW_METHODS, method)
        }
        // 10. If each of the header field-names is a simple header and none is Content-Type, this step may be skipped.
        //
        //     Add one or more Access-Control-Allow-Headers headers consisting of (a subset of) the list of headers.
        //
        //     Note: If a header field name is a simple header and is not Content-Type, it is not required to be listed.
        //           Content-Type is to be listed as only a subset of its values makes it qualify as simple header.
        //
        //     Note: Since the list of headers can be unbounded, simply returning supported headers from
        //           Access-Control-Allow-Headers can be enough.
        if (policies.listOfHeaders.isNotEmpty()) {
            response.setHeader(RESP_HEADER_AC_ALLOW_HEADERS, policies.listOfHeaders.joinToString(", "))
        } else if (headerFieldNames.isNotEmpty()) {
            response.setHeader(RESP_HEADER_AC_ALLOW_HEADERS, headerFieldNames.joinToString(", "))
        }
        // Continue filter chain or set response status
        when {
            policies.preflightContinueChain -> chain.doFilter(request, response)
            policies.preflightPreferNoContent -> response.status = HttpServletResponse.SC_NO_CONTENT
            else -> response.status = HttpServletResponse.SC_OK
        }
    }

    /**
     * Destroy.
     *
     * Currently this is a NO-OP.
     */
    override fun destroy() {
        // NO-OP
    }
}

/**
 * XML Element for Cross-Origin Resource Sharing (CORS) Policies.
 *
 * ```
 * &lt;cors-policies&gt;
 *     &lt;origins&gt;
 *         &lt;origin&gt;...&lt;/origin&gt;
 *         &lt;origin&gt;...&lt;/origin&gt;
 *         &lt;origin&gt;...&lt;/origin&gt;
 *     &lt;/origins&gt;
 *     &lt;methods&gt;
 *         &lt;method&gt;...&lt;/method&gt;
 *         &lt;method&gt;...&lt;/method&gt;
 *         &lt;method&gt;...&lt;/method&gt;
 *     &lt;/methods&gt;
 *     &lt;headers&gt;
 *         &lt;header&gt;...&lt;/header&gt;
 *         &lt;header&gt;...&lt;/header&gt;
 *         &lt;header&gt;...&lt;/header&gt;
 *     &lt;/headers&gt;
 *     &lt;exposed-headers&gt;
 *         &lt;header&gt;...&lt;/header&gt;
 *         &lt;header&gt;...&lt;/header&gt;
 *         &lt;header&gt;...&lt;/header&gt;
 *     &lt;/exposed-headers&gt;
 *     &lt;supports-credentials&gt;false&lt;/supports-credentials&gt;
 *     &lt;access-control-max-age&gt;-1&lt;/access-control-max-age&gt;
 *     &lt;preflight-continue-chain&gt;false&lt;/preflight-continue-chain&gt;
 *     &lt;preflight-prefer-no-content&gt;false&lt;/preflight-prefer-no-content&gt;
 * &lt;/cors-policies&gt;
 * ```
 */
@XmlRootElement(name = "cors-policies")
@XmlType(name = "cors-policies")
@XmlAccessorType(XmlAccessType.PROPERTY)
class CORSPoliciesElement : CORSPolicies {

    @get:XmlElementWrapper(name = "origins", nillable = false, required = false)
    @get:XmlElement(name = "origin", nillable = false, required = false)
    override var listOfOrigins: MutableList<String> = mutableListOf()

    @get:XmlElementWrapper(name = "methods", nillable = false, required = false)
    @get:XmlElement(name = "method", nillable = false, required = false)
    override var listOfMethods: MutableList<String> = mutableListOf()

    @get:XmlElementWrapper(name = "headers", nillable = false, required = false)
    @get:XmlElement(name = "header", nillable = false, required = false)
    override var listOfHeaders: MutableList<String> = mutableListOf()

    @get:XmlElementWrapper(name = "exposed-headers", nillable = false, required = false)
    @get:XmlElement(name = "header", nillable = false, required = false)
    override var listOfExposedHeaders: MutableList<String> = mutableListOf()

    @get:XmlElement(name = "supports-credentials", nillable = false, required = false)
    override var supportsCredentials: Boolean = false

    @get:XmlElement(name = "access-control-max-age", nillable = false, required = false)
    override var accessControlMaxAge: Int = -1

    @get:XmlElement(name = "preflight-continue-chain", nillable = false, required = false)
    override var preflightContinueChain: Boolean = false

    @get:XmlElement(name = "preflight-prefer-no-content", nillable = false, required = false)
    override var preflightPreferNoContent: Boolean = false
}

/**
 * Cross-Origin Resource Sharing (CORS) Policies
 */
interface CORSPolicies {
    /**
     * List of origins. A list of origins consisting of zero or more origins
     * that are allowed access to the resource.
     *
     * An empty list is considered an unbounded list of origins.
     */
    val listOfOrigins: List<String>
    /**
     * List of methods. A list of methods consisting of zero or more methods
     * that are supported by the resource.
     *
     * An empty list is considered an unbounded list of methods.
     */
    val listOfMethods: List<String>
    /**
     * List of headers. A list of headers consisting of zero or more header
     * field names that are supported by the resource.
     *
     * An empty list is considered an unbounded list of headers.
     */
    val listOfHeaders: List<String>
    /**
     * List of exposed headers. A list of exposed headers consisting of zero or
     * more header field names of headers other than the simple response
     * headers that the resource might use and can be exposed.
     *
     * An empty list will not add any exposed header to response.
     */
    val listOfExposedHeaders: List<String>
    /**
     * Supports credentials. A supports credentials flag that indicates whether
     * the resource supports user credentials in the request. It is true when
     * the resource does and false otherwise.
     */
    val supportsCredentials: Boolean
    /**
     * Access control max age.
     */
    val accessControlMaxAge: Int
    /**
     * Preflight should continue filter chain.
     *
     * A value of "true" will call "filter.doChain()", a value of "false"
     * will just set the status in response.
     */
    val preflightContinueChain: Boolean
    /**
     * Preflight should use status 204.
     *
     * A value of "true" will set status in response to 204, a value of "false"
     * will set status in response to 200.
     */
    val preflightPreferNoContent: Boolean
}