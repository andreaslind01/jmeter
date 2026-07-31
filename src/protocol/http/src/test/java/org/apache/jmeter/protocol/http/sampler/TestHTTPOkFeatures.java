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
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URL;
import java.util.List;

import org.apache.jmeter.protocol.http.control.AuthManager;
import org.apache.jmeter.protocol.http.control.CacheManager;
import org.apache.jmeter.protocol.http.util.HTTPConstants;
import org.junit.jupiter.api.Test;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;

import okhttp3.Protocol;

class TestHTTPOkFeatures {

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

    private static HTTPSamplerBase newSampler() {
        return HTTPSamplerFactory.newInstance("OkHttp");
    }

    private static WireMockServer createServer() {
        return new WireMockServer(WireMockConfiguration.wireMockConfig().dynamicPort());
    }
}
