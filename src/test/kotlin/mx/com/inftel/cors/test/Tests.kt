package mx.com.inftel.cors.test

import mx.com.inftel.cors.*
import org.junit.jupiter.api.Test
import org.mockito.ArgumentMatchers
import org.mockito.Mockito.*
import java.util.*
import javax.servlet.FilterChain
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class CORSServletFilter : AbstractCORSServletFilter() {

    public override var listOfOrigins: List<String> = emptyList()
    public override var listOfMethods: List<String> = emptyList()
    public override var listOfHeaders: List<String> = emptyList()
    public override var listOfExposedHeaders: List<String> = emptyList()
    public override var supportsCredentials: Boolean = false
    public override var accessControlMaxAge: Int = -1
    public override var preflightContinueChain: Boolean = false
    public override var preflightPreferNoContent: Boolean = false
}

class RegularRequest {

    @Test
    fun request() {
        val httpServletRequest = mock(HttpServletRequest::class.java)
        val httpServletResponse = mock(HttpServletResponse::class.java)
        val filterChain = mock(FilterChain::class.java)

        `when`(httpServletRequest.method).thenReturn("POST")

        val corsServletFilter = CORSServletFilter()
        corsServletFilter.doFilter(httpServletRequest, httpServletResponse, filterChain)

        verify(httpServletResponse, never()).setHeader(ArgumentMatchers.anyString(), ArgumentMatchers.anyString())
        verify(httpServletResponse, never()).addHeader(ArgumentMatchers.anyString(), ArgumentMatchers.anyString())
        verify(filterChain).doFilter(httpServletRequest, httpServletResponse)
    }
}

class ActualRequest {

    @Test
    fun request() {
        val httpServletRequest = mock(HttpServletRequest::class.java)
        val httpServletResponse = mock(HttpServletResponse::class.java)
        val filterChain = mock(FilterChain::class.java)

        `when`(httpServletRequest.method).thenReturn("POST")
        `when`(httpServletRequest.getHeader(REQ_HEADER_ORIGIN)).thenReturn("http://abc.com:8080/")

        val corsServletFilter = CORSServletFilter()
        corsServletFilter.doFilter(httpServletRequest, httpServletResponse, filterChain)

        verify(httpServletResponse).setHeader(RESP_HEADER_AC_ALLOW_ORIGIN, "*")
        verify(filterChain).doFilter(httpServletRequest, httpServletResponse)
    }

    @Test
    fun `request with credentials support`() {
        val httpServletRequest = mock(HttpServletRequest::class.java)
        val httpServletResponse = mock(HttpServletResponse::class.java)
        val filterChain = mock(FilterChain::class.java)

        `when`(httpServletRequest.method).thenReturn("POST")
        `when`(httpServletRequest.getHeader(REQ_HEADER_ORIGIN)).thenReturn("http://abc.com:8080/")

        val corsServletFilter = CORSServletFilter()
        corsServletFilter.supportsCredentials = true
        corsServletFilter.doFilter(httpServletRequest, httpServletResponse, filterChain)

        verify(httpServletResponse).setHeader(RESP_HEADER_AC_ALLOW_ORIGIN, "http://abc.com:8080/")
        verify(httpServletResponse).setHeader(RESP_HEADER_AC_ALLOW_CREDENTIALS, "true")
        verify(filterChain).doFilter(httpServletRequest, httpServletResponse)
    }

    @Test
    fun `request with list of origins (matching)`() {
        val httpServletRequest = mock(HttpServletRequest::class.java)
        val httpServletResponse = mock(HttpServletResponse::class.java)
        val filterChain = mock(FilterChain::class.java)

        `when`(httpServletRequest.method).thenReturn("POST")
        `when`(httpServletRequest.getHeader(REQ_HEADER_ORIGIN)).thenReturn("http://abc.com:8080/")

        val corsServletFilter = CORSServletFilter()
        corsServletFilter.listOfOrigins = listOf("http://abc.com:8080/")
        corsServletFilter.doFilter(httpServletRequest, httpServletResponse, filterChain)

        verify(httpServletResponse).setHeader(RESP_HEADER_AC_ALLOW_ORIGIN, "*")
        verify(filterChain).doFilter(httpServletRequest, httpServletResponse)
    }

    @Test
    fun `request with list of origins (not matching)`() {
        val httpServletRequest = mock(HttpServletRequest::class.java)
        val httpServletResponse = mock(HttpServletResponse::class.java)
        val filterChain = mock(FilterChain::class.java)

        `when`(httpServletRequest.method).thenReturn("POST")
        `when`(httpServletRequest.getHeader(REQ_HEADER_ORIGIN)).thenReturn("http://abc.com:8080/")

        val corsServletFilter = CORSServletFilter()
        corsServletFilter.listOfOrigins = listOf("http://def.com:8080/")
        corsServletFilter.doFilter(httpServletRequest, httpServletResponse, filterChain)

        verify(httpServletResponse, never()).setHeader(ArgumentMatchers.anyString(), ArgumentMatchers.anyString())
        verify(httpServletResponse, never()).addHeader(ArgumentMatchers.anyString(), ArgumentMatchers.anyString())
        verify(filterChain).doFilter(httpServletRequest, httpServletResponse)
    }

    @Test
    fun `request with list of exposed headers`() {
        val httpServletRequest = mock(HttpServletRequest::class.java)
        val httpServletResponse = mock(HttpServletResponse::class.java)
        val filterChain = mock(FilterChain::class.java)

        `when`(httpServletRequest.method).thenReturn("POST")
        `when`(httpServletRequest.getHeader(REQ_HEADER_ORIGIN)).thenReturn("http://abc.com:8080/")

        val corsServletFilter = CORSServletFilter()
        corsServletFilter.listOfExposedHeaders = listOf("Content-Length", "WWW-Authenticate", "Server-Authorization")
        corsServletFilter.doFilter(httpServletRequest, httpServletResponse, filterChain)

        verify(httpServletResponse).setHeader(RESP_HEADER_AC_ALLOW_ORIGIN, "*")
        verify(httpServletResponse).setHeader(RESP_HEADER_AC_EXPOSE_HEADERS, "Content-Length, WWW-Authenticate, Server-Authorization")
        verify(filterChain).doFilter(httpServletRequest, httpServletResponse)
    }
}

class OptionsRequest {

    @Test
    fun request() {
        val httpServletRequest = mock(HttpServletRequest::class.java)
        val httpServletResponse = mock(HttpServletResponse::class.java)
        val filterChain = mock(FilterChain::class.java)

        `when`(httpServletRequest.method).thenReturn("OPTIONS")
        `when`(httpServletRequest.getHeader(REQ_HEADER_ORIGIN)).thenReturn("http://abc.com:8080/")

        val corsServletFilter = CORSServletFilter()
        corsServletFilter.doFilter(httpServletRequest, httpServletResponse, filterChain)

        verify(httpServletResponse, never()).setHeader(ArgumentMatchers.anyString(), ArgumentMatchers.anyString())
        verify(httpServletResponse, never()).addHeader(ArgumentMatchers.anyString(), ArgumentMatchers.anyString())
        verify(filterChain).doFilter(httpServletRequest, httpServletResponse)
    }
}

class PreflightRequest {

    @Test
    fun request() {
        val httpServletRequest = mock(HttpServletRequest::class.java)
        val httpServletResponse = mock(HttpServletResponse::class.java)
        val filterChain = mock(FilterChain::class.java)

        `when`(httpServletRequest.method).thenReturn("OPTIONS")
        `when`(httpServletRequest.getHeader(REQ_HEADER_ORIGIN)).thenReturn("http://abc.com:8080/")
        `when`(httpServletRequest.getHeader(REQ_HEADER_AC_REQUEST_METHOD)).thenReturn("POST")
        `when`(httpServletRequest.getHeaders(REQ_HEADER_AC_REQUEST_HEADERS)).thenReturn(Collections.emptyEnumeration())

        val corsServletFilter = CORSServletFilter()
        corsServletFilter.doFilter(httpServletRequest, httpServletResponse, filterChain)

        verify(httpServletResponse).setHeader(RESP_HEADER_AC_ALLOW_ORIGIN, "*")
        verify(httpServletResponse).setHeader(RESP_HEADER_AC_ALLOW_METHODS, "POST")
        verify(httpServletResponse, never()).setHeader(RESP_HEADER_AC_ALLOW_HEADERS, "")
        verify(httpServletResponse, never()).setHeader(RESP_HEADER_AC_MAX_AGE, "")
        verify(httpServletResponse).status = HttpServletResponse.SC_OK
        verify(filterChain, never()).doFilter(httpServletRequest, httpServletResponse)
    }

    @Test
    fun `request headers`() {
        val httpServletRequest = mock(HttpServletRequest::class.java)
        val httpServletResponse = mock(HttpServletResponse::class.java)
        val filterChain = mock(FilterChain::class.java)

        `when`(httpServletRequest.method).thenReturn("OPTIONS")
        `when`(httpServletRequest.getHeader(REQ_HEADER_ORIGIN)).thenReturn("http://abc.com:8080/")
        `when`(httpServletRequest.getHeader(REQ_HEADER_AC_REQUEST_METHOD)).thenReturn("POST")
        `when`(httpServletRequest.getHeaders(REQ_HEADER_AC_REQUEST_HEADERS)).thenReturn(Collections.enumeration(listOf("X-CSRF", "X-Requested-With")))

        val corsServletFilter = CORSServletFilter()
        corsServletFilter.doFilter(httpServletRequest, httpServletResponse, filterChain)

        verify(httpServletResponse).setHeader(RESP_HEADER_AC_ALLOW_ORIGIN, "*")
        verify(httpServletResponse).setHeader(RESP_HEADER_AC_ALLOW_METHODS, "POST")
        verify(httpServletResponse).setHeader(RESP_HEADER_AC_ALLOW_HEADERS, "X-CSRF, X-Requested-With")
        verify(httpServletResponse, never()).setHeader(RESP_HEADER_AC_MAX_AGE, "")
        verify(httpServletResponse).status = HttpServletResponse.SC_OK
        verify(filterChain, never()).doFilter(httpServletRequest, httpServletResponse)
    }

    @Test
    fun `request with max age`() {
        val httpServletRequest = mock(HttpServletRequest::class.java)
        val httpServletResponse = mock(HttpServletResponse::class.java)
        val filterChain = mock(FilterChain::class.java)

        `when`(httpServletRequest.method).thenReturn("OPTIONS")
        `when`(httpServletRequest.getHeader(REQ_HEADER_ORIGIN)).thenReturn("http://abc.com:8080/")
        `when`(httpServletRequest.getHeader(REQ_HEADER_AC_REQUEST_METHOD)).thenReturn("POST")
        `when`(httpServletRequest.getHeaders(REQ_HEADER_AC_REQUEST_HEADERS)).thenReturn(Collections.emptyEnumeration())

        val corsServletFilter = CORSServletFilter()
        corsServletFilter.accessControlMaxAge = 300
        corsServletFilter.doFilter(httpServletRequest, httpServletResponse, filterChain)

        verify(httpServletResponse).setHeader(RESP_HEADER_AC_ALLOW_ORIGIN, "*")
        verify(httpServletResponse).setHeader(RESP_HEADER_AC_ALLOW_METHODS, "POST")
        verify(httpServletResponse, never()).setHeader(RESP_HEADER_AC_ALLOW_HEADERS, "")
        verify(httpServletResponse).setHeader(RESP_HEADER_AC_MAX_AGE, "300")
        verify(httpServletResponse).status = HttpServletResponse.SC_OK
        verify(filterChain, never()).doFilter(httpServletRequest, httpServletResponse)
    }

    @Test
    fun `request with chain`() {
        val httpServletRequest = mock(HttpServletRequest::class.java)
        val httpServletResponse = mock(HttpServletResponse::class.java)
        val filterChain = mock(FilterChain::class.java)

        `when`(httpServletRequest.method).thenReturn("OPTIONS")
        `when`(httpServletRequest.getHeader(REQ_HEADER_ORIGIN)).thenReturn("http://abc.com:8080/")
        `when`(httpServletRequest.getHeader(REQ_HEADER_AC_REQUEST_METHOD)).thenReturn("POST")
        `when`(httpServletRequest.getHeaders(REQ_HEADER_AC_REQUEST_HEADERS)).thenReturn(Collections.emptyEnumeration())

        val corsServletFilter = CORSServletFilter()
        corsServletFilter.preflightContinueChain = true
        corsServletFilter.doFilter(httpServletRequest, httpServletResponse, filterChain)

        verify(httpServletResponse).setHeader(RESP_HEADER_AC_ALLOW_ORIGIN, "*")
        verify(httpServletResponse).setHeader(RESP_HEADER_AC_ALLOW_METHODS, "POST")
        verify(httpServletResponse, never()).setHeader(RESP_HEADER_AC_ALLOW_HEADERS, "")
        verify(httpServletResponse, never()).setHeader(RESP_HEADER_AC_MAX_AGE, "")
        verify(filterChain).doFilter(httpServletRequest, httpServletResponse)
    }

    @Test
    fun `request with no content`() {
        val httpServletRequest = mock(HttpServletRequest::class.java)
        val httpServletResponse = mock(HttpServletResponse::class.java)
        val filterChain = mock(FilterChain::class.java)

        `when`(httpServletRequest.method).thenReturn("OPTIONS")
        `when`(httpServletRequest.getHeader(REQ_HEADER_ORIGIN)).thenReturn("http://abc.com:8080/")
        `when`(httpServletRequest.getHeader(REQ_HEADER_AC_REQUEST_METHOD)).thenReturn("POST")
        `when`(httpServletRequest.getHeaders(REQ_HEADER_AC_REQUEST_HEADERS)).thenReturn(Collections.emptyEnumeration())

        val corsServletFilter = CORSServletFilter()
        corsServletFilter.preflightPreferNoContent = true
        corsServletFilter.doFilter(httpServletRequest, httpServletResponse, filterChain)

        verify(httpServletResponse).setHeader(RESP_HEADER_AC_ALLOW_ORIGIN, "*")
        verify(httpServletResponse).setHeader(RESP_HEADER_AC_ALLOW_METHODS, "POST")
        verify(httpServletResponse, never()).setHeader(RESP_HEADER_AC_ALLOW_HEADERS, "")
        verify(httpServletResponse, never()).setHeader(RESP_HEADER_AC_MAX_AGE, "")
        verify(httpServletResponse).status = HttpServletResponse.SC_NO_CONTENT
        verify(filterChain, never()).doFilter(httpServletRequest, httpServletResponse)
    }

    @Test
    fun `request with credentials support`() {
        val httpServletRequest = mock(HttpServletRequest::class.java)
        val httpServletResponse = mock(HttpServletResponse::class.java)
        val filterChain = mock(FilterChain::class.java)

        `when`(httpServletRequest.method).thenReturn("OPTIONS")
        `when`(httpServletRequest.getHeader(REQ_HEADER_ORIGIN)).thenReturn("http://abc.com:8080/")
        `when`(httpServletRequest.getHeader(REQ_HEADER_AC_REQUEST_METHOD)).thenReturn("POST")
        `when`(httpServletRequest.getHeaders(REQ_HEADER_AC_REQUEST_HEADERS)).thenReturn(Collections.emptyEnumeration())

        val corsServletFilter = CORSServletFilter()
        corsServletFilter.supportsCredentials = true
        corsServletFilter.doFilter(httpServletRequest, httpServletResponse, filterChain)

        verify(httpServletResponse).setHeader(RESP_HEADER_AC_ALLOW_ORIGIN, "http://abc.com:8080/")
        verify(httpServletResponse).setHeader(RESP_HEADER_AC_ALLOW_CREDENTIALS, "true")
        verify(httpServletResponse).setHeader(RESP_HEADER_AC_ALLOW_METHODS, "POST")
        verify(httpServletResponse, never()).setHeader(RESP_HEADER_AC_ALLOW_HEADERS, "")
        verify(httpServletResponse, never()).setHeader(RESP_HEADER_AC_MAX_AGE, "")
        verify(httpServletResponse).status = HttpServletResponse.SC_OK
        verify(filterChain, never()).doFilter(httpServletRequest, httpServletResponse)
    }

    @Test
    fun `request with list of methods (matching)`() {
        val httpServletRequest = mock(HttpServletRequest::class.java)
        val httpServletResponse = mock(HttpServletResponse::class.java)
        val filterChain = mock(FilterChain::class.java)

        `when`(httpServletRequest.method).thenReturn("OPTIONS")
        `when`(httpServletRequest.getHeader(REQ_HEADER_ORIGIN)).thenReturn("http://abc.com:8080/")
        `when`(httpServletRequest.getHeader(REQ_HEADER_AC_REQUEST_METHOD)).thenReturn("POST")
        `when`(httpServletRequest.getHeaders(REQ_HEADER_AC_REQUEST_HEADERS)).thenReturn(Collections.emptyEnumeration())

        val corsServletFilter = CORSServletFilter()
        corsServletFilter.listOfMethods = listOf("GET", "POST")
        corsServletFilter.doFilter(httpServletRequest, httpServletResponse, filterChain)

        verify(httpServletResponse).setHeader(RESP_HEADER_AC_ALLOW_ORIGIN, "*")
        verify(httpServletResponse).setHeader(RESP_HEADER_AC_ALLOW_METHODS, "GET, POST")
        verify(httpServletResponse, never()).setHeader(RESP_HEADER_AC_ALLOW_HEADERS, "")
        verify(httpServletResponse, never()).setHeader(RESP_HEADER_AC_MAX_AGE, "")
        verify(httpServletResponse).status = HttpServletResponse.SC_OK
        verify(filterChain, never()).doFilter(httpServletRequest, httpServletResponse)
    }

    @Test
    fun `request with list of methods (not matching)`() {
        val httpServletRequest = mock(HttpServletRequest::class.java)
        val httpServletResponse = mock(HttpServletResponse::class.java)
        val filterChain = mock(FilterChain::class.java)

        `when`(httpServletRequest.method).thenReturn("OPTIONS")
        `when`(httpServletRequest.getHeader(REQ_HEADER_ORIGIN)).thenReturn("http://abc.com:8080/")
        `when`(httpServletRequest.getHeader(REQ_HEADER_AC_REQUEST_METHOD)).thenReturn("POST")
        `when`(httpServletRequest.getHeaders(REQ_HEADER_AC_REQUEST_HEADERS)).thenReturn(Collections.emptyEnumeration())

        val corsServletFilter = CORSServletFilter()
        corsServletFilter.listOfMethods = listOf("PUT", "DELETE")
        corsServletFilter.doFilter(httpServletRequest, httpServletResponse, filterChain)

        verify(httpServletResponse, never()).setHeader(ArgumentMatchers.anyString(), ArgumentMatchers.anyString())
        verify(httpServletResponse, never()).addHeader(ArgumentMatchers.anyString(), ArgumentMatchers.anyString())
        verify(filterChain).doFilter(httpServletRequest, httpServletResponse)
    }

    @Test
    fun `request with list of headers (matching)`() {
        val httpServletRequest = mock(HttpServletRequest::class.java)
        val httpServletResponse = mock(HttpServletResponse::class.java)
        val filterChain = mock(FilterChain::class.java)

        `when`(httpServletRequest.method).thenReturn("OPTIONS")
        `when`(httpServletRequest.getHeader(REQ_HEADER_ORIGIN)).thenReturn("http://abc.com:8080/")
        `when`(httpServletRequest.getHeader(REQ_HEADER_AC_REQUEST_METHOD)).thenReturn("POST")
        `when`(httpServletRequest.getHeaders(REQ_HEADER_AC_REQUEST_HEADERS)).thenReturn(Collections.enumeration(listOf("Authorization")))

        val corsServletFilter = CORSServletFilter()
        corsServletFilter.listOfHeaders = listOf("Authorization", "X-Requested-With")
        corsServletFilter.doFilter(httpServletRequest, httpServletResponse, filterChain)

        verify(httpServletResponse).setHeader(RESP_HEADER_AC_ALLOW_ORIGIN, "*")
        verify(httpServletResponse).setHeader(RESP_HEADER_AC_ALLOW_METHODS, "POST")
        verify(httpServletResponse).setHeader(RESP_HEADER_AC_ALLOW_HEADERS, "Authorization, X-Requested-With")
        verify(httpServletResponse, never()).setHeader(RESP_HEADER_AC_MAX_AGE, "")
        verify(httpServletResponse).status = HttpServletResponse.SC_OK
        verify(filterChain, never()).doFilter(httpServletRequest, httpServletResponse)
    }

    @Test
    fun `request with list of headers (not matching)`() {
        val httpServletRequest = mock(HttpServletRequest::class.java)
        val httpServletResponse = mock(HttpServletResponse::class.java)
        val filterChain = mock(FilterChain::class.java)

        `when`(httpServletRequest.method).thenReturn("OPTIONS")
        `when`(httpServletRequest.getHeader(REQ_HEADER_ORIGIN)).thenReturn("http://abc.com:8080/")
        `when`(httpServletRequest.getHeader(REQ_HEADER_AC_REQUEST_METHOD)).thenReturn("POST")
        `when`(httpServletRequest.getHeaders(REQ_HEADER_AC_REQUEST_HEADERS)).thenReturn(Collections.enumeration(listOf("X-CSRF")))

        val corsServletFilter = CORSServletFilter()
        corsServletFilter.listOfHeaders = listOf("Authorization", "X-Requested-With")
        corsServletFilter.doFilter(httpServletRequest, httpServletResponse, filterChain)

        verify(httpServletResponse, never()).setHeader(ArgumentMatchers.anyString(), ArgumentMatchers.anyString())
        verify(httpServletResponse, never()).addHeader(ArgumentMatchers.anyString(), ArgumentMatchers.anyString())
        verify(filterChain).doFilter(httpServletRequest, httpServletResponse)
    }
}
