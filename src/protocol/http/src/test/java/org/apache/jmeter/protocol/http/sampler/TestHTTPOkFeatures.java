/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to you under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.jmeter.protocol.http.sampler;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;

import javax.security.auth.Subject;

import org.apache.jmeter.junit.JMeterTestCase;
import org.apache.jmeter.protocol.http.control.AuthManager;
import org.apache.jmeter.protocol.http.control.CacheManager;
import org.apache.jmeter.protocol.http.util.HTTPConstants;
import org.apache.jmeter.util.JMeterUtils;
import org.junit.jupiter.api.Test;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;

import okhttp3.Credentials;
import okhttp3.HttpUrl;
import okhttp3.OkHttpClient;
import okhttp3.Protocol;
import okhttp3.Request;
import okhttp3.Response;

class TestHTTPOkFeatures extends JMeterTestCase {

    private static final String RETRY_PROPERTY = "okhttp.retry_on_connection_failure";

    private static final String STALE_RETRY_PROPERTY = "okhttp.stale_connection_retries";

    @Test
    void usesSamplerHttpVersionWhenSpecified() {
        assertEquals(List.of(Protocol.HTTP_1_1), HTTPOkImpl.getProtocols("HTTP/1.1", "HTTP/2", "https"));
        assertEquals(List.of(Protocol.HTTP_2, Protocol.HTTP_1_1), HTTPOkImpl.getProtocols("HTTP/2", "HTTP/1.1", "https"));
    }

    @Test
    void defaultsToHttp11ForUnsupportedHttpVersion() {
        assertEquals(List.of(Protocol.HTTP_1_1), HTTPOkImpl.getProtocols("HTTP/3", "HTTP/2", "https"));
    }

    @Test
    void negotiatesHttp2OverTls() {
        assertEquals(List.of(Protocol.HTTP_2, Protocol.HTTP_1_1), HTTPOkImpl.getProtocols("HTTP/2", "HTTP/1.1", "https"));
    }

    @Test
    void negotiatesHttp2ForStrictHttp2() {
        assertEquals(List.of(Protocol.HTTP_2, Protocol.HTTP_1_1),
                HTTPOkImpl.getProtocols("HTTP/2 Strict", "HTTP/1.1", "https"));
    }

    @Test
    void usesHttp2WhenSelected() throws Exception {
        WireMockServer server = new WireMockServer(WireMockConfiguration.wireMockConfig()
                .dynamicHttpsPort()
                .http2TlsDisabled(false));
        try {
            server.start();
            server.stubFor(get(urlEqualTo("/http2")).willReturn(aResponse().withStatus(200)));
            HTTPSamplerBase sampler = newSampler();
            sampler.setHttpVersion("HTTP/2");

            HTTPSampleResult result = sampler.sample(
                    new URL("https://localhost:" + server.httpsPort() + "/http2"), HTTPConstants.GET, false, 1);

            assertEquals("200", result.getResponseCode());
            assertEquals("HTTP/2", result.getResponseHeaders().substring(0, "HTTP/2".length()));
        } finally {
            server.stop();
        }
    }

    @Test
    void latencyDoesNotExceedElapsedTimeForDribbledHttp2Response() throws Exception {
        WireMockServer server = new WireMockServer(WireMockConfiguration.wireMockConfig()
                .dynamicHttpsPort()
                .http2TlsDisabled(false));
        server.start();
        try {
            server.stubFor(get(urlEqualTo("/http2dribbled"))
                    .willReturn(aResponse().withStatus(200).withBody(new byte[10_000]).withChunkedDribbleDelay(5, 500)));
            HTTPSamplerBase sampler = newSampler();
            sampler.setHttpVersion("HTTP/2");

            HTTPSampleResult result = sampler.sample(
                    new URL("https://localhost:" + server.httpsPort() + "/http2dribbled"), HTTPConstants.GET, false, 1);

            assertTrue(result.getLatency() <= result.getTime(),
                    "latency should not exceed elapsed time");
        } finally {
            server.stop();
        }
    }

    @Test
    void fallsBackToHttp11WhenServerDoesNotSupportHttp2() throws Exception {
        WireMockServer server = new WireMockServer(WireMockConfiguration.wireMockConfig()
                .dynamicHttpsPort()
                .http2TlsDisabled(true));
        try {
            server.start();
            server.stubFor(get(urlEqualTo("/fallback")).willReturn(aResponse().withStatus(200)));
            HTTPSamplerBase sampler = newSampler();
            sampler.setHttpVersion("HTTP/2");

            HTTPSampleResult result = sampler.sample(
                    new URL("https://localhost:" + server.httpsPort() + "/fallback"), HTTPConstants.GET, false, 1);

            assertEquals("200", result.getResponseCode());
            assertEquals("HTTP/1.1", result.getResponseHeaders().substring(0, "HTTP/1.1".length()));
        } finally {
            server.stop();
        }
    }

    @Test
    void usesHttp11WhenSelected() throws Exception {
        WireMockServer server = createServer();
        server.start();
        try {
            server.stubFor(get(urlEqualTo("/http11")).willReturn(aResponse().withStatus(200)));
            HTTPSamplerBase sampler = newSampler();
            sampler.setHttpVersion("HTTP/1.1");

            HTTPSampleResult result = sampler.sample(
                    new URL(server.url("/http11")), HTTPConstants.GET, false, 1);

            assertEquals("200", result.getResponseCode());
            assertEquals("HTTP/1.1", result.getResponseHeaders().substring(0, "HTTP/1.1".length()));
        } finally {
            server.stop();
        }
    }

    @Test
    void latencyDoesNotExceedElapsedTimeForDribbledHttp11Response() throws Exception {
        WireMockServer server = createServer();
        server.start();
        try {
            server.stubFor(get(urlEqualTo("/http11dribbled"))
                    .willReturn(aResponse().withStatus(200).withBody(new byte[10_000]).withChunkedDribbleDelay(5, 500)));
            HTTPSamplerBase sampler = newSampler();
            sampler.setHttpVersion("HTTP/1.1");

            HTTPSampleResult result = sampler.sample(
                    new URL(server.url("/http11dribbled")), HTTPConstants.GET, false, 1);

            assertTrue(result.getLatency() <= result.getTime(),
                    "latency should not exceed elapsed time");
        } finally {
            server.stop();
        }
    }

    @Test
    void setsSentBytesCorrectlyForGetRequest() throws Exception {
        WireMockServer server = createServer();
        server.start();
        try {
            server.stubFor(get(urlEqualTo("/sentBytesGet")).willReturn(aResponse().withStatus(200)));
            HTTPSamplerBase sampler = newSampler();
            sampler.setHttpVersion("HTTP/1.1");

            HTTPSampleResult result = sampler.sample(
                    new URL(server.url("/sentBytesGet")), HTTPConstants.GET, false, 1);

            assertEquals("200", result.getResponseCode());
            assertTrue(result.getSentBytes() > 0, "sentBytes should be greater than 0");
        } finally {
            server.stop();
        }
    }

    @Test
    void setsSentBytesCorrectlyForPostRequest() throws Exception {
        WireMockServer server = createServer();
        server.start();
        try {
            server.stubFor(post(urlEqualTo("/sentBytesPost")).willReturn(aResponse().withStatus(200)));
            HTTPSamplerBase sampler = newSampler();
            sampler.setHttpVersion("HTTP/1.1");
            sampler.setPostBodyRaw(true);
            sampler.addNonEncodedArgument("", "hello world", "");

            HTTPSampleResult result = sampler.sample(
                    new URL(server.url("/sentBytesPost")), HTTPConstants.POST, false, 1);

            assertEquals("200", result.getResponseCode());
            assertTrue(result.getSentBytes() > "hello world".length(), "sentBytes should include request line, headers, and body");
        } finally {
            server.stop();
        }
    }

    @Test
    void sendsConditionalRequestForCachedResource() throws Exception {
        WireMockServer server = createServer();
        server.start();
        try {
            server.stubFor(get(urlEqualTo("/cache"))
                    .willReturn(aResponse().withHeader("ETag", "cache-tag").withStatus(200)));
            HTTPSamplerBase sampler = newSampler();
            sampler.setCacheManager(new CacheManager());
            URL url = new URL(server.url("/cache"));

            assertEquals("200", sampler.sample(url, HTTPConstants.GET, false, 1).getResponseCode());
            assertEquals("200", sampler.sample(url, HTTPConstants.GET, false, 1).getResponseCode());

            server.verify(1, getRequestedFor(urlEqualTo("/cache"))
                    .withHeader("If-None-Match", WireMock.equalTo("cache-tag")));
        } finally {
            server.stop();
        }
    }

    @Test
    void sendsBasicCredentialsFromAuthorizationManager() throws Exception {
        WireMockServer server = createServer();
        server.start();
        try {
            server.stubFor(get(urlEqualTo("/auth"))
                    .withHeader("Authorization", WireMock.equalTo("Basic dXNlcjpwYXNz"))
                    .willReturn(aResponse().withStatus(200)));
            server.stubFor(get(urlEqualTo("/auth")).atPriority(10)
                    .willReturn(aResponse().withHeader("WWW-Authenticate", "Basic realm=\"test\"").withStatus(401)));
            AuthManager authManager = new AuthManager();
            authManager.set(-1, server.url("/"), "user", "pass", "", "", AuthManager.Mechanism.BASIC);
            HTTPSamplerBase sampler = newSampler();
            sampler.setAuthManager(authManager);

            assertEquals("200", sampler.sample(new URL(server.url("/auth")), HTTPConstants.GET, false, 1).getResponseCode());
        } finally {
            server.stop();
        }
    }

    @Test
    void authenticatesWithConfiguredProxyCredentials() throws Exception {
        WireMockServer server = createServer();
        server.start();
        try {
            server.stubFor(get(urlEqualTo("/proxy"))
                    .withHeader("Proxy-Authorization", WireMock.equalTo("Basic dXNlcjpwYXNz"))
                    .willReturn(aResponse().withStatus(200)));
            server.stubFor(get(urlEqualTo("/proxy")).atPriority(10)
                    .willReturn(aResponse().withHeader("Proxy-Authenticate", "Basic realm=\"proxy\"").withStatus(407)));
            HTTPSamplerBase sampler = newSampler();
            sampler.setProxyHost("localhost");
            sampler.setProxyPortInt(Integer.toString(server.port()));
            sampler.setProxyUser("user");
            sampler.setProxyPass("pass");

            assertEquals("200", sampler.sample(new URL(server.url("/proxy")), HTTPConstants.GET, false, 1).getResponseCode());
        } finally {
            server.stop();
        }
    }

    @Test
    void setsConnectTimeForHttp2() throws Exception {
        WireMockServer server = new WireMockServer(WireMockConfiguration.wireMockConfig()
                .dynamicHttpsPort()
                .http2TlsDisabled(false));
        server.start();
        try {
            server.stubFor(get(urlEqualTo("/connectTime2")).willReturn(aResponse().withStatus(200)));
            HTTPSamplerBase sampler = newSampler();
            sampler.setHttpVersion("HTTP/2");

            HTTPSampleResult result = sampler.sample(
                    new URL("https://localhost:" + server.httpsPort() + "/connectTime2"), HTTPConstants.GET, false, 1);

            assertEquals("200", result.getResponseCode());
            assertTrue(result.getConnectTime() > 0,
                    "connectTime should be greater than 0, but was " + result.getConnectTime());
            assertTrue(result.getConnectTime() <= result.getTime(),
                    "connectTime should not exceed the elapsed time");
        } finally {
            server.stop();
        }
    }

    @Test
    void doesNotRetryClientTimeoutResponses() throws Exception {
        WireMockServer server = createServer();
        server.start();
        try {
            server.stubFor(get(urlEqualTo("/retry408")).willReturn(aResponse().withStatus(408)));
            HTTPSamplerBase sampler = newSampler();

            HTTPSampleResult result = sampler.sample(
                    new URL(server.url("/retry408")), HTTPConstants.GET, false, 1);

            assertEquals("408", result.getResponseCode());
            server.verify(1, getRequestedFor(urlEqualTo("/retry408")));
        } finally {
            server.stop();
        }
    }

    @Test
    void retriesClientTimeoutResponsesWhenConfigured() throws Exception {
        WireMockServer server = createServer();
        server.start();
        String oldValue = JMeterUtils.getProperty(RETRY_PROPERTY);
        JMeterUtils.setProperty(RETRY_PROPERTY, "true");
        try {
            server.stubFor(get(urlEqualTo("/retry408")).willReturn(aResponse().withStatus(408)));
            HTTPSamplerBase sampler = newSampler();

            HTTPSampleResult result = sampler.sample(
                    new URL(server.url("/retry408")), HTTPConstants.GET, false, 1);

            assertEquals("408", result.getResponseCode());
            server.verify(2, getRequestedFor(urlEqualTo("/retry408")));
        } finally {
            if (oldValue == null) {
                JMeterUtils.getJMeterProperties().remove(RETRY_PROPERTY);
            } else {
                JMeterUtils.setProperty(RETRY_PROPERTY, oldValue);
            }
            server.stop();
        }
    }

    @Test
    void attachesKerberosContextForKerberosAuthorization() throws Exception {
        AuthManager authManager = new AuthManager();
        authManager.set(-1, "http://kerberos.example.invalid/", "user", "pass", "", "",
                AuthManager.Mechanism.KERBEROS);
        URL url = new URL("http://kerberos.example.invalid/protected");
        Request.Builder requestBuilder = new Request.Builder().url(url);

        HTTPOkImpl.setupAuthorization(url, requestBuilder, authManager, authManager.getAuthForURL(url));
        Request request = requestBuilder.build();

        assertNull(request.header(HTTPConstants.HEADER_AUTHORIZATION),
                "the credentials of a Kerberos authorization are only used to log in to the KDC");
        assertNotNull(request.tag(SpnegoAuthenticator.KerberosContext.class),
                "the request needs the Kerberos data to answer a Negotiate challenge");
    }

    @Test
    void doesNotAttachKerberosContextForBasicAuthorization() throws Exception {
        AuthManager authManager = new AuthManager();
        authManager.set(-1, "http://basic.example.invalid/", "user", "pass", "", "", AuthManager.Mechanism.BASIC);
        URL url = new URL("http://basic.example.invalid/protected");
        Request.Builder requestBuilder = new Request.Builder().url(url);

        HTTPOkImpl.setupAuthorization(url, requestBuilder, authManager, authManager.getAuthForURL(url));
        Request request = requestBuilder.build();

        assertEquals("Basic dXNlcjpwYXNz", request.header(HTTPConstants.HEADER_AUTHORIZATION));
        assertNull(request.tag(SpnegoAuthenticator.KerberosContext.class));
    }

    @Test
    void ignoresChallengesOfRequestsWithoutKerberosAuthorization() throws Exception {
        Response response = unauthorizedResponse(new Request.Builder()
                .url("http://kerberos.example.invalid/protected").build(), "Negotiate");

        assertNull(SpnegoAuthenticator.INSTANCE.authenticate(null, response),
                "requests without a Kerberos authorization must not be retried");
    }

    @Test
    void ignoresResponsesWithoutNegotiateChallenge() throws Exception {
        URL url = new URL("http://kerberos.example.invalid/protected");
        Request request = new Request.Builder()
                .url(url)
                .tag(SpnegoAuthenticator.KerberosContext.class,
                        new SpnegoAuthenticator.KerberosContext(null, url))
                .build();

        assertNull(SpnegoAuthenticator.INSTANCE.authenticate(null, unauthorizedResponse(request, "Basic realm=\"x\"")),
                "a server that does not offer Negotiate must not get a SPNEGO token");
    }

    @Test
    void doesNotRepeatRejectedSpnegoTokens() throws Exception {
        URL url = new URL("http://kerberos.example.invalid/protected");
        Request request = new Request.Builder()
                .url(url)
                .header(HTTPConstants.HEADER_AUTHORIZATION, "Negotiate token")
                .tag(SpnegoAuthenticator.KerberosContext.class,
                        new SpnegoAuthenticator.KerberosContext(null, url))
                .build();

        assertNull(SpnegoAuthenticator.INSTANCE.authenticate(null, unauthorizedResponse(request, "Negotiate")),
                "a rejected token must not be sent again to avoid an endless loop");
    }

    @Test
    void failsGracefullyWhenTheNegotiateChallengeCannotBeAnswered() throws Exception {
        WireMockServer server = createServer();
        server.start();
        try {
            server.stubFor(get(urlEqualTo("/kerberos")).willReturn(aResponse()
                    .withHeader("WWW-Authenticate", "Negotiate").withStatus(401)));
            AuthManager authManager = new AuthManager();
            authManager.set(-1, server.url("/"), "user", "pass", "", "", AuthManager.Mechanism.KERBEROS);
            HTTPSamplerBase sampler = newSampler();
            sampler.setAuthManager(authManager);

            HTTPSampleResult result = sampler.sample(
                    new URL(server.url("/kerberos")), HTTPConstants.GET, false, 1);

            assertEquals("401", result.getResponseCode(),
                    "a failed negotiation has to report the response of the server");
        } finally {
            server.stop();
        }
    }

    @Test
    void usesTheSpnegoAuthenticatorForNegotiateChallenges() throws Exception {
        HTTPSamplerBase sampler = newSampler();
        HTTPOkImpl implementation = new HTTPOkImpl(sampler);

        OkHttpClient client = HTTPOkImpl.createClient(
                implementation.createHttpClientKey(new URL("http://kerberos.example.invalid/protected")));

        assertSame(SpnegoAuthenticator.INSTANCE, client.authenticator(),
                "the client has to answer Negotiate challenges with a SPNEGO token");
    }

    @Test
    void sendsTheSpnegoTokenAfterANegotiateChallenge() throws Exception {
        URL url = new URL("http://kerberos.example.invalid/protected");
        Request request = new Request.Builder()
                .url(url)
                .tag(SpnegoAuthenticator.KerberosContext.class,
                        new SpnegoAuthenticator.KerberosContext(null, url))
                .build();
        SpnegoAuthenticator authenticator =
                new SpnegoAuthenticator((authServer, input) -> ("token-for-" + authServer).getBytes(UTF_8));

        Request retry = authenticator.authenticate(null, unauthorizedResponse(request, "Negotiate"));

        assertNotNull(retry, "the challenged request has to be repeated with a SPNEGO token");
        assertEquals("Negotiate " + Base64.getEncoder()
                        .encodeToString("token-for-kerberos.example.invalid".getBytes(UTF_8)),
                retry.header(HTTPConstants.HEADER_AUTHORIZATION));
    }

    @Test
    void parsesTheTokenOfTheNegotiateChallenge() {
        Request request = new Request.Builder().url("http://kerberos.example.invalid/protected").build();

        assertEquals("", SpnegoAuthenticator.getNegotiateChallenge(unauthorizedResponse(request, "Negotiate")));
        assertEquals("", SpnegoAuthenticator.getNegotiateChallenge(unauthorizedResponse(request, "negotiate")));
        assertEquals("", SpnegoAuthenticator.getNegotiateChallenge(unauthorizedResponse(request, "Negotiate, NTLM")));
        assertEquals("a1b2", SpnegoAuthenticator.getNegotiateChallenge(unauthorizedResponse(request, "Negotiate a1b2")));
        assertNull(SpnegoAuthenticator.getNegotiateChallenge(unauthorizedResponse(request, "NTLM")));
        assertNull(SpnegoAuthenticator.getNegotiateChallenge(unauthorizedResponse(request, "NegotiateX realm=\"x\"")));
    }

    @Test
    void stripsThePortFromTheServicePrincipalName() {
        HttpUrl url = HttpUrl.get("http://kerberos.example.invalid:8080/protected");

        assertEquals("kerberos.example.invalid", SpnegoAuthenticator.getAuthServer(url, true));
        assertEquals("kerberos.example.invalid:8080", SpnegoAuthenticator.getAuthServer(url, false));
    }

    @Test
    void answersNegotiateProxyChallengeWithASpnegoToken() throws Exception {
        Request request = new Request.Builder().url("http://target.example.invalid/resource").build();
        SpnegoProxyAuthenticator authenticator = new SpnegoProxyAuthenticator("proxy.example.invalid", 8080,
                "", "", (authServer, input) -> ("token-for-" + authServer).getBytes(UTF_8));

        Request retry = authenticator.authenticate(null, proxyAuthenticationRequiredResponse(request, "Negotiate"));

        assertNotNull(retry, "the challenge of the proxy has to be answered");
        assertEquals("Negotiate " + Base64.getEncoder()
                        .encodeToString("token-for-proxy.example.invalid".getBytes(UTF_8)),
                retry.header("Proxy-Authorization"),
                "the SPNEGO token has to be built for the proxy, not for the target");
    }

    @Test
    void prefersTheConfiguredProxyCredentialsOverNegotiate() throws Exception {
        Request request = new Request.Builder().url("http://target.example.invalid/resource").build();
        SpnegoProxyAuthenticator authenticator = new SpnegoProxyAuthenticator("proxy.example.invalid", 8080,
                "user", "pass", (authServer, input) -> ("token-for-" + authServer).getBytes(UTF_8));

        Request retry = authenticator.authenticate(null, proxyAuthenticationRequiredResponse(request, "Negotiate"));

        assertNotNull(retry, "the challenge of the proxy has to be answered");
        assertEquals(Credentials.basic("user", "pass"), retry.header("Proxy-Authorization"),
                "a proxy with configured credentials must not switch to Kerberos");
    }

    @Test
    void usesTheProxySubjectOfTheAuthorizationManagerForNegotiate() throws Exception {
        Request request = new Request.Builder().url("http://target.example.invalid/resource").build();
        SpnegoProxyAuthenticator authenticator = new SpnegoProxyAuthenticator("proxy.example.invalid", 8080,
                "user", "pass", (authServer, input) -> ("token-for-" + authServer).getBytes(UTF_8));
        SpnegoProxyAuthenticator.setSubject(new Subject());
        try {
            Request retry = authenticator.authenticate(null, proxyAuthenticationRequiredResponse(request, "Negotiate"));

            assertNotNull(retry, "the challenge of the proxy has to be answered");
            assertEquals("Negotiate " + Base64.getEncoder()
                            .encodeToString("token-for-proxy.example.invalid".getBytes(UTF_8)),
                    retry.header("Proxy-Authorization"),
                    "a Kerberos entry of the authorization manager has to win over the proxy password");
        } finally {
            SpnegoProxyAuthenticator.clearSubject();
        }
    }

    @Test
    void doesNotRepeatRejectedProxyCredentials() throws Exception {
        Request request = new Request.Builder()
                .url("http://target.example.invalid/resource")
                .header("Proxy-Authorization", "Negotiate token")
                .build();
        SpnegoProxyAuthenticator authenticator = new SpnegoProxyAuthenticator("proxy.example.invalid", 8080,
                "", "", (authServer, input) -> ("token-for-" + authServer).getBytes(UTF_8));

        assertNull(authenticator.authenticate(null, proxyAuthenticationRequiredResponse(request, "Negotiate")),
                "a rejected token must not be sent again to avoid an endless loop");
    }

    @Test
    void ignoresProxyChallengesWithoutCredentials() throws Exception {
        Request request = new Request.Builder().url("http://target.example.invalid/resource").build();
        SpnegoProxyAuthenticator authenticator = new SpnegoProxyAuthenticator("proxy.example.invalid", 8080,
                "", "", (authServer, input) -> ("token-for-" + authServer).getBytes(UTF_8));

        assertNull(authenticator.authenticate(null,
                        proxyAuthenticationRequiredResponse(request, "Basic realm=\"proxy\"")),
                "a Basic challenge cannot be answered without configured proxy credentials");
    }

    @Test
    void usesTheProxyAuthenticatorForProxiesWithoutCredentials() throws Exception {
        HTTPSamplerBase sampler = newSampler();
        sampler.setProxyHost("proxy.example.invalid");
        sampler.setProxyPortInt("8080");
        HTTPOkImpl implementation = new HTTPOkImpl(sampler);

        OkHttpClient client = HTTPOkImpl.createClient(
                implementation.createHttpClientKey(new URL("http://target.example.invalid/resource")));

        assertTrue(client.proxyAuthenticator() instanceof SpnegoProxyAuthenticator,
                "a Negotiate challenge of the proxy has to be answered with a SPNEGO token");
    }

    @Test
    void repeatsRequestWhenTheServerClosedThePooledConnection() throws Exception {
        try (ClosingKeepAliveServer server = new ClosingKeepAliveServer()) {
            HTTPSamplerBase sampler = newSampler();
            sampler.setHttpVersion("HTTP/1.1");
            URL url = new URL("http://localhost:" + server.getPort() + "/stale");

            assertEquals("200", sampler.sample(url, HTTPConstants.GET, false, 1).getResponseCode());
            server.awaitClosedConnections(1);
            HTTPSampleResult result = sampler.sample(url, HTTPConstants.GET, false, 1);

            assertEquals("200", result.getResponseCode(),
                    "a connection the server closed while it was idle has to be replaced silently");
            assertEquals(2, server.getRequestCount(),
                    "the server must not see the request of the dead connection twice");
        }
    }

    @Test
    void reportsTheClosedPooledConnectionWhenTheRetryIsDisabled() throws Exception {
        String oldValue = JMeterUtils.getProperty(STALE_RETRY_PROPERTY);
        JMeterUtils.setProperty(STALE_RETRY_PROPERTY, "0");
        try (ClosingKeepAliveServer server = new ClosingKeepAliveServer()) {
            HTTPSamplerBase sampler = newSampler();
            sampler.setHttpVersion("HTTP/1.1");
            URL url = new URL("http://localhost:" + server.getPort() + "/stale");

            assertEquals("200", sampler.sample(url, HTTPConstants.GET, false, 1).getResponseCode());
            server.awaitClosedConnections(1);
            HTTPSampleResult result = sampler.sample(url, HTTPConstants.GET, false, 1);

            assertFalse(result.isSuccessful(), "without the retry the dead connection fails the sample");
            assertTrue(result.getResponseCode().startsWith("Non HTTP response code"),
                    "expected an IO failure, but got " + result.getResponseCode());
        } finally {
            if (oldValue == null) {
                JMeterUtils.getJMeterProperties().remove(STALE_RETRY_PROPERTY);
            } else {
                JMeterUtils.setProperty(STALE_RETRY_PROPERTY, oldValue);
            }
        }
    }

    @Test
    void doesNotRepeatRequestWhenTheServerDropsANewConnection() throws Exception {
        try (ClosingKeepAliveServer server = new ClosingKeepAliveServer(true)) {
            HTTPSamplerBase sampler = newSampler();
            sampler.setHttpVersion("HTTP/1.1");
            URL url = new URL("http://localhost:" + server.getPort() + "/dropped");

            HTTPSampleResult result = sampler.sample(url, HTTPConstants.GET, false, 1);

            assertFalse(result.isSuccessful(),
                    "a server that drops a fresh connection has to fail the sample");
            assertEquals(1, server.getRequestCount(), "a fresh connection must not be retried");
        }
    }

    @Test
    void repeatsRequestUntilAFreshConnectionIsUsedWhenAllPooledConnectionsAreDead() throws Exception {
        int parallel = 4;
        try (ClosingKeepAliveServer server = new ClosingKeepAliveServer(false, 300)) {
            URL url = new URL("http://localhost:" + server.getPort() + "/parallel");
            // Concurrent samples fill the pool with connections which the server closes afterwards,
            // like the parallel downloads of the embedded resources of a page do
            ExecutorService downloads = Executors.newFixedThreadPool(parallel);
            try {
                List<Future<HTTPSampleResult>> results = new ArrayList<>();
                for (int i = 0; i < parallel; i++) {
                    results.add(downloads.submit(() -> newSampler().sample(url, HTTPConstants.GET, false, 1)));
                }
                for (Future<HTTPSampleResult> result : results) {
                    assertEquals("200", result.get().getResponseCode());
                }
                server.awaitClosedConnections(parallel);

                for (int i = 0; i < parallel; i++) {
                    Future<HTTPSampleResult> result =
                            downloads.submit(() -> newSampler().sample(url, HTTPConstants.GET, false, 1));
                    assertEquals("200", result.get().getResponseCode(),
                            "a pool full of connections the server closed has to be drained silently");
                }
            } finally {
                downloads.shutdownNow();
            }
        }
    }

    /**
     * Answers every request with a keep alive response, but closes the connection right afterwards,
     * like a server (or a load balancer) that gives up on an idle connection.
     */
    private static final class ClosingKeepAliveServer implements AutoCloseable {
        private final ServerSocket serverSocket;
        private final AtomicInteger requestCount = new AtomicInteger();
        private final AtomicInteger closedConnections = new AtomicInteger();
        private final Thread acceptor;
        private final boolean dropWithoutResponse;
        private final long responseDelayMillis;

        ClosingKeepAliveServer() throws IOException {
            this(false, 0);
        }

        ClosingKeepAliveServer(boolean dropWithoutResponse) throws IOException {
            this(dropWithoutResponse, 0);
        }

        ClosingKeepAliveServer(boolean dropWithoutResponse, long responseDelayMillis) throws IOException {
            this.dropWithoutResponse = dropWithoutResponse;
            this.responseDelayMillis = responseDelayMillis;
            serverSocket = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
            acceptor = new Thread(this::acceptConnections, "closing-keep-alive-server");
            acceptor.setDaemon(true);
            acceptor.start();
        }

        private void acceptConnections() {
            while (!serverSocket.isClosed()) {
                try {
                    Socket socket = serverSocket.accept();
                    Thread handler = new Thread(() -> handleConnection(socket), "closing-keep-alive-handler");
                    handler.setDaemon(true);
                    handler.start();
                } catch (IOException e) {
                    return;
                }
            }
        }

        private void handleConnection(Socket socket) {
            try (Socket connection = socket) {
                readRequest(connection);
                requestCount.incrementAndGet();
                if (!dropWithoutResponse) {
                    if (responseDelayMillis > 0) {
                        Thread.sleep(responseDelayMillis);
                    }
                    connection.getOutputStream().write(
                            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".getBytes(UTF_8));
                    connection.getOutputStream().flush();
                }
            } catch (IOException e) {
                // the connection is closed anyway
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } finally {
                closedConnections.incrementAndGet();
            }
        }

        private static void readRequest(Socket socket) throws IOException {
            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream(), UTF_8));
            String line = reader.readLine();
            while (line != null && !line.isEmpty()) {
                line = reader.readLine();
            }
        }

        void awaitClosedConnections(int expected) throws InterruptedException {
            for (int i = 0; i < 100 && closedConnections.get() < expected; i++) {
                Thread.sleep(20);
            }
        }

        int getPort() {
            return serverSocket.getLocalPort();
        }

        int getRequestCount() {
            return requestCount.get();
        }

        @Override
        public void close() throws IOException {
            serverSocket.close();
            acceptor.interrupt();
        }
    }

    private static Response proxyAuthenticationRequiredResponse(Request request, String challenge) {
        return new Response.Builder()
                .request(request)
                .protocol(Protocol.HTTP_1_1)
                .code(407)
                .message("Proxy Authentication Required")
                .header("Proxy-Authenticate", challenge)
                .build();
    }

    private static Response unauthorizedResponse(Request request, String challenge) {
        return new Response.Builder()
                .request(request)
                .protocol(Protocol.HTTP_1_1)
                .code(401)
                .message("Unauthorized")
                .header("WWW-Authenticate", challenge)
                .build();
    }

    private static HTTPSamplerBase newSampler() {
        return HTTPSamplerFactory.newInstance("OkHttp");
    }

    private static WireMockServer createServer() {
        return new WireMockServer(WireMockConfiguration.wireMockConfig().dynamicPort());
    }
}
