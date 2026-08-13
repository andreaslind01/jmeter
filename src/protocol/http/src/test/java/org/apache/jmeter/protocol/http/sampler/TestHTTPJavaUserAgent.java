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
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URL;
import java.util.List;

import org.apache.jmeter.junit.JMeterTestCase;
import org.apache.jmeter.protocol.http.control.Header;
import org.apache.jmeter.protocol.http.control.HeaderManager;
import org.apache.jmeter.protocol.http.util.HTTPConstants;
import org.junit.jupiter.api.Test;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.github.tomakehurst.wiremock.verification.LoggedRequest;

class TestHTTPJavaUserAgent extends JMeterTestCase {

    @Test
    void sendsDefaultUserAgentForHttp11ByDefault() throws Exception {
        WireMockServer server = createServer();
        server.start();
        try {
            server.stubFor(get(urlEqualTo("/defaultUa11")).willReturn(aResponse().withStatus(200)));
            HTTPSamplerBase sampler = newSampler("HTTP/1.1");

            HTTPSampleResult result = sampler.sample(
                    new URL(server.url("/defaultUa11")), HTTPConstants.GET, false, 1);

            assertEquals("200", result.getResponseCode());
            assertEquals("Java/" + System.getProperty("java.version"),
                    loggedRequest(server, "/defaultUa11").getHeader("User-Agent"));
            assertTrue(result.getRequestHeaders().contains("User-Agent: Java/"),
                    "request headers of the sample result: " + result.getRequestHeaders());
        } finally {
            server.stop();
        }
    }

    @Test
    void sendsDefaultUserAgentForHttp2ByDefault() throws Exception {
        WireMockServer server = createServer();
        server.start();
        try {
            server.stubFor(get(urlEqualTo("/defaultUa2")).willReturn(aResponse().withStatus(200)));
            HTTPSamplerBase sampler = newSampler("HTTP/2");

            HTTPSampleResult result = sampler.sample(
                    new URL(server.url("/defaultUa2")), HTTPConstants.GET, false, 1);

            assertEquals("200", result.getResponseCode());
            assertEquals("Java-http-client/" + System.getProperty("java.version"),
                    loggedRequest(server, "/defaultUa2").getHeader("User-Agent"));
            assertTrue(result.getRequestHeaders().contains("User-Agent: Java-http-client/"),
                    "request headers of the sample result: " + result.getRequestHeaders());
        } finally {
            server.stop();
        }
    }

    @Test
    void keepsConfiguredUserAgentForHttp11() throws Exception {
        WireMockServer server = createServer();
        server.start();
        try {
            server.stubFor(get(urlEqualTo("/ownUa11")).willReturn(aResponse().withStatus(200)));
            HTTPSamplerBase sampler = newSampler("HTTP/1.1");
            sampler.setHeaderManager(userAgentHeaderManager());

            HTTPSampleResult result = sampler.sample(
                    new URL(server.url("/ownUa11")), HTTPConstants.GET, false, 1);

            assertEquals("200", result.getResponseCode());
            assertEquals("JMeter-Test-Agent", loggedRequest(server, "/ownUa11").getHeader("User-Agent"));
        } finally {
            server.stop();
        }
    }

    @Test
    void keepsConfiguredUserAgentForHttp2() throws Exception {
        WireMockServer server = createServer();
        server.start();
        try {
            server.stubFor(get(urlEqualTo("/ownUa2")).willReturn(aResponse().withStatus(200)));
            HTTPSamplerBase sampler = newSampler("HTTP/2");
            sampler.setHeaderManager(userAgentHeaderManager());

            HTTPSampleResult result = sampler.sample(
                    new URL(server.url("/ownUa2")), HTTPConstants.GET, false, 1);

            assertEquals("200", result.getResponseCode());
            assertEquals("JMeter-Test-Agent", loggedRequest(server, "/ownUa2").getHeader("User-Agent"));
        } finally {
            server.stop();
        }
    }

    private static HeaderManager userAgentHeaderManager() {
        HeaderManager headerManager = new HeaderManager();
        headerManager.add(new Header("User-Agent", "JMeter-Test-Agent"));
        return headerManager;
    }

    private static LoggedRequest loggedRequest(WireMockServer server, String url) {
        List<LoggedRequest> requests = server.findAll(getRequestedFor(urlEqualTo(url)));
        assertEquals(1, requests.size(), "number of requests to " + url);
        return requests.get(0);
    }

    private static HTTPSamplerBase newSampler(String httpVersion) {
        HTTPSamplerBase sampler = HTTPSamplerFactory.newInstance("Java");
        sampler.setHttpVersion(httpVersion);
        return sampler;
    }

    private static WireMockServer createServer() {
        return new WireMockServer(WireMockConfiguration.wireMockConfig().dynamicPort());
    }
}
