package mx.com.inftel.cors.test

import mx.com.inftel.cors.*
import org.junit.jupiter.api.Test
import org.mockito.ArgumentMatchers
import org.mockito.Mockito.*
import java.util.*
import javax.servlet.FilterChain
import javax.servlet.FilterConfig
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class TestCORSServletFilter : AbstractCORSServletFilter() {

    public override val policies: TestCORSPolicy = TestCORSPolicy()
}

class TestCORSPolicy : CORSPolicies {

    override var listOfOrigins: List<String> = emptyList()
    override var listOfMethods: List<String> = emptyList()
    override var listOfHeaders: List<String> = emptyList()
    override var listOfExposedHeaders: List<String> = emptyList()
    override var supportsCredentials: Boolean = false
    override var accessControlMaxAge: Int = -1
    override var preflightContinueChain: Boolean = false
    override var preflightPreferNoContent: Boolean = false
}

class RegularRequest {

    @Test
    fun request() {
        val httpServletRequest = mock(HttpServletRequest::class.java)
        val httpServletResponse = mock(HttpServletResponse::class.java)
        val filterChain = mock(FilterChain::class.java)

        `when`(httpServletRequest.method).thenReturn("POST")

        val corsServletFilter = TestCORSServletFilter()
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
        `when`(httpServletRequest.getHeader("Origin")).thenReturn("http://abc.com:8080")

        val corsServletFilter = TestCORSServletFilter()
        corsServletFilter.doFilter(httpServletRequest, httpServletResponse, filterChain)

        verify(httpServletResponse, times(1)).setHeader("Access-Control-Allow-Origin", "*")
        verify(filterChain).doFilter(httpServletRequest, httpServletResponse)
    }

    @Test
    fun `request with credentials support`() {
        val httpServletRequest = mock(HttpServletRequest::class.java)
        val httpServletResponse = mock(HttpServletResponse::class.java)
        val filterChain = mock(FilterChain::class.java)

        `when`(httpServletRequest.method).thenReturn("POST")
        `when`(httpServletRequest.getHeader("Origin")).thenReturn("http://abc.com:8080")

        val corsServletFilter = TestCORSServletFilter()
        corsServletFilter.policies.supportsCredentials = true
        corsServletFilter.doFilter(httpServletRequest, httpServletResponse, filterChain)

        verify(httpServletResponse, times(1)).setHeader("Access-Control-Allow-Origin", "http://abc.com:8080")
        verify(httpServletResponse, times(1)).setHeader("Access-Control-Allow-Credentials", "true")
        verify(filterChain).doFilter(httpServletRequest, httpServletResponse)
    }

    @Test
    fun `request with list of origins (matching)`() {
        val httpServletRequest = mock(HttpServletRequest::class.java)
        val httpServletResponse = mock(HttpServletResponse::class.java)
        val filterChain = mock(FilterChain::class.java)

        `when`(httpServletRequest.method).thenReturn("POST")
        `when`(httpServletRequest.getHeader("Origin")).thenReturn("http://abc.com:8080")

        val corsServletFilter = TestCORSServletFilter()
        corsServletFilter.policies.listOfOrigins = listOf("http://abc.com:8080")
        corsServletFilter.doFilter(httpServletRequest, httpServletResponse, filterChain)

        verify(httpServletResponse, times(1)).setHeader("Access-Control-Allow-Origin", "*")
        verify(filterChain).doFilter(httpServletRequest, httpServletResponse)
    }

    @Test
    fun `request with list of origins (not matching)`() {
        val httpServletRequest = mock(HttpServletRequest::class.java)
        val httpServletResponse = mock(HttpServletResponse::class.java)
        val filterChain = mock(FilterChain::class.java)

        `when`(httpServletRequest.method).thenReturn("POST")
        `when`(httpServletRequest.getHeader("Origin")).thenReturn("http://abc.com:8080")

        val corsServletFilter = TestCORSServletFilter()
        corsServletFilter.policies.listOfOrigins = listOf("http://def.com:8080")
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
        `when`(httpServletRequest.getHeader("Origin")).thenReturn("http://abc.com:8080")

        val corsServletFilter = TestCORSServletFilter()
        corsServletFilter.policies.listOfExposedHeaders = listOf("Content-Length", "WWW-Authenticate", "Server-Authorization")
        corsServletFilter.doFilter(httpServletRequest, httpServletResponse, filterChain)

        verify(httpServletResponse, times(1)).setHeader("Access-Control-Allow-Origin", "*")
        verify(httpServletResponse, times(1)).setHeader("Access-Control-Expose-Headers", "Content-Length, WWW-Authenticate, Server-Authorization")
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
        `when`(httpServletRequest.getHeader("Origin")).thenReturn("http://abc.com:8080")

        val corsServletFilter = TestCORSServletFilter()
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
        `when`(httpServletRequest.getHeader("Origin")).thenReturn("http://abc.com:8080")
        `when`(httpServletRequest.getHeader("Access-Control-Request-Method")).thenReturn("POST")
        `when`(httpServletRequest.getHeaders("Access-Control-Request-Headers")).thenReturn(Collections.emptyEnumeration())

        val corsServletFilter = TestCORSServletFilter()
        corsServletFilter.doFilter(httpServletRequest, httpServletResponse, filterChain)

        verify(httpServletResponse, times(1)).setHeader("Access-Control-Allow-Origin", "*")
        verify(httpServletResponse, times(1)).setHeader("Access-Control-Allow-Methods", "POST")
        verify(httpServletResponse, never()).setHeader("Access-Control-Allow-Headers", "")
        verify(httpServletResponse, never()).setHeader("Access-Control-Max-Age", "")
        verify(httpServletResponse, times(1)).status = HttpServletResponse.SC_OK
        verify(filterChain, never()).doFilter(httpServletRequest, httpServletResponse)
    }

    @Test
    fun `request headers`() {
        val httpServletRequest = mock(HttpServletRequest::class.java)
        val httpServletResponse = mock(HttpServletResponse::class.java)
        val filterChain = mock(FilterChain::class.java)

        `when`(httpServletRequest.method).thenReturn("OPTIONS")
        `when`(httpServletRequest.getHeader("Origin")).thenReturn("http://abc.com:8080")
        `when`(httpServletRequest.getHeader("Access-Control-Request-Method")).thenReturn("POST")
        `when`(httpServletRequest.getHeaders("Access-Control-Request-Headers")).thenReturn(Collections.enumeration(listOf("X-CSRF", "X-Requested-With")))

        val corsServletFilter = TestCORSServletFilter()
        corsServletFilter.doFilter(httpServletRequest, httpServletResponse, filterChain)

        verify(httpServletResponse, times(1)).setHeader("Access-Control-Allow-Origin", "*")
        verify(httpServletResponse, times(1)).setHeader("Access-Control-Allow-Methods", "POST")
        verify(httpServletResponse, times(1)).setHeader("Access-Control-Allow-Headers", "X-CSRF, X-Requested-With")
        verify(httpServletResponse, never()).setHeader("Access-Control-Max-Age", "")
        verify(httpServletResponse, times(1)).status = HttpServletResponse.SC_OK
        verify(filterChain, never()).doFilter(httpServletRequest, httpServletResponse)
    }

    @Test
    fun `request with max age`() {
        val httpServletRequest = mock(HttpServletRequest::class.java)
        val httpServletResponse = mock(HttpServletResponse::class.java)
        val filterChain = mock(FilterChain::class.java)

        `when`(httpServletRequest.method).thenReturn("OPTIONS")
        `when`(httpServletRequest.getHeader("Origin")).thenReturn("http://abc.com:8080")
        `when`(httpServletRequest.getHeader("Access-Control-Request-Method")).thenReturn("POST")
        `when`(httpServletRequest.getHeaders("Access-Control-Request-Headers")).thenReturn(Collections.emptyEnumeration())

        val corsServletFilter = TestCORSServletFilter()
        corsServletFilter.policies.accessControlMaxAge = 300
        corsServletFilter.doFilter(httpServletRequest, httpServletResponse, filterChain)

        verify(httpServletResponse, times(1)).setHeader("Access-Control-Allow-Origin", "*")
        verify(httpServletResponse, times(1)).setHeader("Access-Control-Allow-Methods", "POST")
        verify(httpServletResponse, never()).setHeader("Access-Control-Allow-Headers", "")
        verify(httpServletResponse, times(1)).setHeader("Access-Control-Max-Age", "300")
        verify(httpServletResponse, times(1)).status = HttpServletResponse.SC_OK
        verify(filterChain, never()).doFilter(httpServletRequest, httpServletResponse)
    }

    @Test
    fun `request with chain`() {
        val httpServletRequest = mock(HttpServletRequest::class.java)
        val httpServletResponse = mock(HttpServletResponse::class.java)
        val filterChain = mock(FilterChain::class.java)

        `when`(httpServletRequest.method).thenReturn("OPTIONS")
        `when`(httpServletRequest.getHeader("Origin")).thenReturn("http://abc.com:8080")
        `when`(httpServletRequest.getHeader("Access-Control-Request-Method")).thenReturn("POST")
        `when`(httpServletRequest.getHeaders("Access-Control-Request-Headers")).thenReturn(Collections.emptyEnumeration())

        val corsServletFilter = TestCORSServletFilter()
        corsServletFilter.policies.preflightContinueChain = true
        corsServletFilter.doFilter(httpServletRequest, httpServletResponse, filterChain)

        verify(httpServletResponse, times(1)).setHeader("Access-Control-Allow-Origin", "*")
        verify(httpServletResponse, times(1)).setHeader("Access-Control-Allow-Methods", "POST")
        verify(httpServletResponse, never()).setHeader("Access-Control-Allow-Headers", "")
        verify(httpServletResponse, never()).setHeader("Access-Control-Max-Age", "")
        verify(filterChain).doFilter(httpServletRequest, httpServletResponse)
    }

    @Test
    fun `request with no content`() {
        val httpServletRequest = mock(HttpServletRequest::class.java)
        val httpServletResponse = mock(HttpServletResponse::class.java)
        val filterChain = mock(FilterChain::class.java)

        `when`(httpServletRequest.method).thenReturn("OPTIONS")
        `when`(httpServletRequest.getHeader("Origin")).thenReturn("http://abc.com:8080")
        `when`(httpServletRequest.getHeader("Access-Control-Request-Method")).thenReturn("POST")
        `when`(httpServletRequest.getHeaders("Access-Control-Request-Headers")).thenReturn(Collections.emptyEnumeration())

        val corsServletFilter = TestCORSServletFilter()
        corsServletFilter.policies.preflightPreferNoContent = true
        corsServletFilter.doFilter(httpServletRequest, httpServletResponse, filterChain)

        verify(httpServletResponse, times(1)).setHeader("Access-Control-Allow-Origin", "*")
        verify(httpServletResponse, times(1)).setHeader("Access-Control-Allow-Methods", "POST")
        verify(httpServletResponse, never()).setHeader("Access-Control-Allow-Headers", "")
        verify(httpServletResponse, never()).setHeader("Access-Control-Max-Age", "")
        verify(httpServletResponse, times(1)).status = HttpServletResponse.SC_NO_CONTENT
        verify(filterChain, never()).doFilter(httpServletRequest, httpServletResponse)
    }

    @Test
    fun `request with credentials support`() {
        val httpServletRequest = mock(HttpServletRequest::class.java)
        val httpServletResponse = mock(HttpServletResponse::class.java)
        val filterChain = mock(FilterChain::class.java)

        `when`(httpServletRequest.method).thenReturn("OPTIONS")
        `when`(httpServletRequest.getHeader("Origin")).thenReturn("http://abc.com:8080")
        `when`(httpServletRequest.getHeader("Access-Control-Request-Method")).thenReturn("POST")
        `when`(httpServletRequest.getHeaders("Access-Control-Request-Headers")).thenReturn(Collections.emptyEnumeration())

        val corsServletFilter = TestCORSServletFilter()
        corsServletFilter.policies.supportsCredentials = true
        corsServletFilter.doFilter(httpServletRequest, httpServletResponse, filterChain)

        verify(httpServletResponse, times(1)).setHeader("Access-Control-Allow-Origin", "http://abc.com:8080")
        verify(httpServletResponse, times(1)).setHeader("Access-Control-Allow-Credentials", "true")
        verify(httpServletResponse, times(1)).setHeader("Access-Control-Allow-Methods", "POST")
        verify(httpServletResponse, never()).setHeader("Access-Control-Allow-Headers", "")
        verify(httpServletResponse, never()).setHeader("Access-Control-Max-Age", "")
        verify(httpServletResponse, times(1)).status = HttpServletResponse.SC_OK
        verify(filterChain, never()).doFilter(httpServletRequest, httpServletResponse)
    }

    @Test
    fun `request with list of methods (matching)`() {
        val httpServletRequest = mock(HttpServletRequest::class.java)
        val httpServletResponse = mock(HttpServletResponse::class.java)
        val filterChain = mock(FilterChain::class.java)

        `when`(httpServletRequest.method).thenReturn("OPTIONS")
        `when`(httpServletRequest.getHeader("Origin")).thenReturn("http://abc.com:8080")
        `when`(httpServletRequest.getHeader("Access-Control-Request-Method")).thenReturn("POST")
        `when`(httpServletRequest.getHeaders("Access-Control-Request-Headers")).thenReturn(Collections.emptyEnumeration())

        val corsServletFilter = TestCORSServletFilter()
        corsServletFilter.policies.listOfMethods = listOf("GET", "POST")
        corsServletFilter.doFilter(httpServletRequest, httpServletResponse, filterChain)

        verify(httpServletResponse, times(1)).setHeader("Access-Control-Allow-Origin", "*")
        verify(httpServletResponse, times(1)).setHeader("Access-Control-Allow-Methods", "GET, POST")
        verify(httpServletResponse, never()).setHeader("Access-Control-Allow-Headers", "")
        verify(httpServletResponse, never()).setHeader("Access-Control-Max-Age", "")
        verify(httpServletResponse, times(1)).status = HttpServletResponse.SC_OK
        verify(filterChain, never()).doFilter(httpServletRequest, httpServletResponse)
    }

    @Test
    fun `request with list of methods (not matching)`() {
        val httpServletRequest = mock(HttpServletRequest::class.java)
        val httpServletResponse = mock(HttpServletResponse::class.java)
        val filterChain = mock(FilterChain::class.java)

        `when`(httpServletRequest.method).thenReturn("OPTIONS")
        `when`(httpServletRequest.getHeader("Origin")).thenReturn("http://abc.com:8080")
        `when`(httpServletRequest.getHeader("Access-Control-Request-Method")).thenReturn("POST")
        `when`(httpServletRequest.getHeaders("Access-Control-Request-Headers")).thenReturn(Collections.emptyEnumeration())

        val corsServletFilter = TestCORSServletFilter()
        corsServletFilter.policies.listOfMethods = listOf("PUT", "DELETE")
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
        `when`(httpServletRequest.getHeader("Origin")).thenReturn("http://abc.com:8080")
        `when`(httpServletRequest.getHeader("Access-Control-Request-Method")).thenReturn("POST")
        `when`(httpServletRequest.getHeaders("Access-Control-Request-Headers")).thenReturn(Collections.enumeration(listOf("Authorization")))

        val corsServletFilter = TestCORSServletFilter()
        corsServletFilter.policies.listOfHeaders = listOf("Authorization", "X-Requested-With")
        corsServletFilter.doFilter(httpServletRequest, httpServletResponse, filterChain)

        verify(httpServletResponse, times(1)).setHeader("Access-Control-Allow-Origin", "*")
        verify(httpServletResponse, times(1)).setHeader("Access-Control-Allow-Methods", "POST")
        verify(httpServletResponse, times(1)).setHeader("Access-Control-Allow-Headers", "Authorization, X-Requested-With")
        verify(httpServletResponse, never()).setHeader("Access-Control-Max-Age", "")
        verify(httpServletResponse, times(1)).status = HttpServletResponse.SC_OK
        verify(filterChain, never()).doFilter(httpServletRequest, httpServletResponse)
    }

    @Test
    fun `request with list of headers (not matching)`() {
        val httpServletRequest = mock(HttpServletRequest::class.java)
        val httpServletResponse = mock(HttpServletResponse::class.java)
        val filterChain = mock(FilterChain::class.java)

        `when`(httpServletRequest.method).thenReturn("OPTIONS")
        `when`(httpServletRequest.getHeader("Origin")).thenReturn("http://abc.com:8080")
        `when`(httpServletRequest.getHeader("Access-Control-Request-Method")).thenReturn("POST")
        `when`(httpServletRequest.getHeaders("Access-Control-Request-Headers")).thenReturn(Collections.enumeration(listOf("X-CSRF")))

        val corsServletFilter = TestCORSServletFilter()
        corsServletFilter.policies.listOfHeaders = listOf("Authorization", "X-Requested-With")
        corsServletFilter.doFilter(httpServletRequest, httpServletResponse, filterChain)

        verify(httpServletResponse, never()).setHeader(ArgumentMatchers.anyString(), ArgumentMatchers.anyString())
        verify(httpServletResponse, never()).addHeader(ArgumentMatchers.anyString(), ArgumentMatchers.anyString())
        verify(filterChain).doFilter(httpServletRequest, httpServletResponse)
    }
}

class XML {

    @Test
    fun xml() {
        val filterConfig = mock(FilterConfig::class.java)

        `when`(filterConfig.getInitParameter("cors-policies")).thenReturn("test-cors-policies.xml")

        val corsServletFilter = object : CORSServletFilter() {

            public override var policies: CORSPolicies
                get() = super.policies
                set(value) {
                    super.policies = value
                }
        }

        corsServletFilter.init(filterConfig)

        if (corsServletFilter.policies.listOfOrigins[0] != "abc") {
            throw Exception("Error loading XML")
        }
        if (corsServletFilter.policies.listOfOrigins[1] != "def") {
            throw Exception("Error loading XML")
        }
        if (corsServletFilter.policies.listOfOrigins[2] != "ghi") {
            throw Exception("Error loading XML")
        }
        if (corsServletFilter.policies.listOfMethods[0] != "OPTIONS") {
            throw Exception("Error loading XML")
        }
        if (corsServletFilter.policies.listOfMethods[1] != "HEAD") {
            throw Exception("Error loading XML")
        }
        if (corsServletFilter.policies.listOfMethods[2] != "GET") {
            throw Exception("Error loading XML")
        }
        if (corsServletFilter.policies.listOfMethods[3] != "POST") {
            throw Exception("Error loading XML")
        }
        if (corsServletFilter.policies.listOfHeaders[0] != "Authorization") {
            throw Exception("Error loading XML")
        }
        if (corsServletFilter.policies.listOfHeaders[1] != "X-CSRF") {
            throw Exception("Error loading XML")
        }
        if (corsServletFilter.policies.listOfHeaders[2] != "X-Requested-With") {
            throw Exception("Error loading XML")
        }
        if (corsServletFilter.policies.listOfExposedHeaders[0] != "Content-Length") {
            throw Exception("Error loading XML")
        }
        if (corsServletFilter.policies.listOfExposedHeaders[1] != "WWW-Authenticate") {
            throw Exception("Error loading XML")
        }
        if (corsServletFilter.policies.listOfExposedHeaders[2] != "Server-Authenticate") {
            throw Exception("Error loading XML")
        }
        if (!corsServletFilter.policies.supportsCredentials) {
            throw Exception("Error loading XML")
        }
        if (corsServletFilter.policies.accessControlMaxAge != -1) {
            throw Exception("Error loading XML")
        }
        if (!corsServletFilter.policies.preflightContinueChain) {
            throw Exception("Error loading XML")
        }
        if (!corsServletFilter.policies.preflightPreferNoContent) {
            throw Exception("Error loading XML")
        }
    }
}