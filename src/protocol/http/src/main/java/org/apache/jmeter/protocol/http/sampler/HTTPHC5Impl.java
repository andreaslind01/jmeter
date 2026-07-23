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

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.URL;
import java.net.URLDecoder;
import java.net.UnknownHostException;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

import org.apache.hc.client5.http.classic.ExecChain;
import org.apache.hc.client5.http.classic.ExecChainHandler;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.entity.BrotliInputStreamFactory;
import org.apache.hc.client5.http.entity.DecompressingEntity;
import org.apache.hc.client5.http.entity.DeflateInputStreamFactory;
import org.apache.hc.client5.http.entity.GZIPInputStreamFactory;
import org.apache.hc.client5.http.entity.InputStreamFactory;
import org.apache.hc.client5.http.entity.UrlEncodedFormEntity;
import org.apache.hc.client5.http.entity.mime.MultipartEntityBuilder;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.impl.routing.DefaultRoutePlanner;
import org.apache.hc.client5.http.protocol.HttpClientContext;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HeaderElement;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.HttpHeaders;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.NameValuePair;
import org.apache.hc.core5.http.config.Lookup;
import org.apache.hc.core5.http.config.RegistryBuilder;
import org.apache.hc.core5.http.io.entity.FileEntity;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.http.message.BasicHeaderValueParser;
import org.apache.hc.core5.http.message.BasicNameValuePair;
import org.apache.hc.core5.http.message.ParserCursor;
import org.apache.hc.core5.util.Timeout;
import org.apache.jmeter.protocol.http.control.CacheManager;
import org.apache.jmeter.protocol.http.control.CookieManager;
import org.apache.jmeter.protocol.http.control.DNSCacheManager;
import org.apache.jmeter.protocol.http.control.HeaderManager;
import org.apache.jmeter.protocol.http.util.HTTPArgument;
import org.apache.jmeter.protocol.http.util.HTTPConstants;
import org.apache.jmeter.protocol.http.util.HTTPFileArg;
import org.apache.jmeter.services.FileServer;
import org.apache.jmeter.testelement.property.CollectionProperty;
import org.apache.jmeter.testelement.property.JMeterProperty;
import org.apache.jmeter.threads.JMeterContextService;
import org.apache.jmeter.threads.JMeterVariables;
import org.apache.jmeter.util.JsseSSLManager;
import org.apache.jmeter.util.SSLManager;
import org.apache.jorphan.util.JOrphanUtils;
import org.apache.jorphan.util.StringUtilities;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * HTTP Sampler using Apache HttpClient 5.x.
 */
public class HTTPHC5Impl extends HTTPHCAbstractImpl {

    private static final Logger log = LoggerFactory.getLogger(HTTPHC5Impl.class);

    private static final ThreadLocal<Map<HttpClientKey, CloseableHttpClient>> HTTP_CLIENTS =
            ThreadLocal.withInitial(HashMap::new);

    private static final String[] HEADERS_TO_SAVE = {HttpHeaders.CONTENT_LENGTH, HttpHeaders.CONTENT_ENCODING,
            HttpHeaders.CONTENT_MD5};

    private static final Lookup<InputStreamFactory> CONTENT_DECODERS = RegistryBuilder.<InputStreamFactory>create()
            .register("br", BrotliInputStreamFactory.getInstance())
            .register("gzip", GZIPInputStreamFactory.getInstance())
            .register("x-gzip", GZIPInputStreamFactory.getInstance())
            .register("deflate", DeflateInputStreamFactory.getInstance())
            .build();

    private static final ExecChainHandler RESPONSE_CONTENT_ENCODING = (request, scope, chain) -> {
        HttpClientContext context = scope.clientContext;
        RequestConfig requestConfig = context.getRequestConfig();
        if (requestConfig == null) {
            requestConfig = RequestConfig.DEFAULT;
        }
        ClassicHttpResponse response = chain.proceed(request, scope);
        HttpEntity entity = response.getEntity();
        if (!requestConfig.isContentCompressionEnabled() || entity == null || entity.getContentLength() == 0
                || entity.getContentEncoding() == null) {
            return response;
        }

        Header[][] headersToSave = new Header[HEADERS_TO_SAVE.length][];
        for (int i = 0; i < HEADERS_TO_SAVE.length; i++) {
            headersToSave[i] = response.getHeaders(HEADERS_TO_SAVE[i]);
        }
        String contentEncoding = entity.getContentEncoding();
        HeaderElement[] codecs = BasicHeaderValueParser.INSTANCE.parseElements(contentEncoding,
                new ParserCursor(0, contentEncoding.length()));
        for (HeaderElement codec : codecs) {
            InputStreamFactory decoderFactory = CONTENT_DECODERS.lookup(codec.getName().toLowerCase(Locale.ROOT));
            if (decoderFactory != null) {
                response.setEntity(new DecompressingEntity(response.getEntity(), decoderFactory));
                response.removeHeaders(HttpHeaders.CONTENT_LENGTH);
                response.removeHeaders(HttpHeaders.CONTENT_ENCODING);
                response.removeHeaders(HttpHeaders.CONTENT_MD5);
            }
        }
        for (Header[] headers : headersToSave) {
            for (Header header : headers) {
                if (!response.containsHeader(header.getName())) {
                    response.addHeader(header);
                }
            }
        }
        return response;
    };

    private volatile org.apache.hc.client5.http.classic.methods.HttpUriRequestBase currentRequest;

    protected HTTPHC5Impl(HTTPSamplerBase testElement) {
        super(testElement);
    }

    @Override
    protected HTTPSampleResult sample(URL url, String method, boolean areFollowingRedirect, int frameDepth) {
        HTTPSampleResult result = createSampleResult(url, method);
        org.apache.hc.client5.http.classic.methods.HttpUriRequestBase request = null;
        ClassicHttpResponse response = null;
        try {
            resetStateIfNeeded();
            request = createRequest(url.toURI(), method);
            setupRequest(url, request, result, areFollowingRedirect);
            result.sampleStart();

            CacheManager cacheManager = getCacheManager();
            if (cacheManager != null && HTTPConstants.GET.equalsIgnoreCase(method)) {
                log.debug("Cache Manager is not supported by HttpClient5 yet");
            }

            currentRequest = request;
            response = getClient(createHttpClientKey(url)).executeOpen(null, request, null);
            result.sampleEnd();
            currentRequest = null;

            updateResult(response, request, result);
            saveConnectionCookies(response, result.getURL(), getCookieManager());
            return resultProcessing(areFollowingRedirect, frameDepth, result);
        } catch (Exception e) {
            if (result.getEndTime() == 0) {
                result.sampleEnd();
            }
            if (request != null) {
                result.setRequestHeaders(getRequestHeaders(request));
            }
            return errorResult(e, result);
        } finally {
            JOrphanUtils.closeQuietly(response);
            currentRequest = null;
        }
    }

    private HTTPSampleResult createSampleResult(URL url, String method) {
        HTTPSampleResult result = new HTTPSampleResult();
        configureSampleLabel(result, url);
        result.setHTTPMethod(method);
        result.setURL(url);
        return result;
    }

    private static org.apache.hc.client5.http.classic.methods.HttpUriRequestBase createRequest(URI uri, String method) {
        return new org.apache.hc.client5.http.classic.methods.HttpUriRequestBase(method, uri);
    }

    private void setupRequest(URL url, org.apache.hc.client5.http.classic.methods.HttpUriRequestBase request,
            HTTPSampleResult result, boolean areFollowingRedirect) throws IOException {
        RequestConfig.Builder config = RequestConfig.custom()
                .setRedirectsEnabled(getAutoRedirects() && !areFollowingRedirect);
        int responseTimeout = getResponseTimeout();
        if (responseTimeout > 0) {
            config.setResponseTimeout(Timeout.ofMilliseconds(responseTimeout));
        }
        request.setConfig(config.build());
        request.setHeader(HTTPConstants.HEADER_CONNECTION,
                getUseKeepAlive() ? HTTPConstants.KEEP_ALIVE : HTTPConstants.CONNECTION_CLOSE);
        setConnectionHeaders(request, getHeaderManager());

        String cookies = setConnectionCookie(request, url, getCookieManager());
        if (StringUtilities.isNotEmpty(cookies)) {
            result.setCookies(cookies);
        } else {
            result.setCookies(getOnlyCookieFromHeaders(request));
        }

        if (canHaveBody(request.getMethod())) {
            result.setQueryString(setupRequestEntity(request));
        }
    }

    private static boolean canHaveBody(String method) {
        return !HTTPConstants.HEAD.equals(method) && !HTTPConstants.TRACE.equals(method);
    }

    private String setupRequestEntity(org.apache.hc.client5.http.classic.methods.HttpUriRequestBase request) throws IOException {
        HTTPFileArg[] files = getHTTPFiles();
        String contentEncoding = getContentEncoding();
        Charset charset = Charset.forName(contentEncoding);
        HttpEntity entity;
        String requestData;
        if (getUseMultipart()) {
            MultipartEntityBuilder builder = MultipartEntityBuilder.create().setCharset(charset);
            for (JMeterProperty property : getArguments().getEnabledArguments()) {
                HTTPArgument argument = (HTTPArgument) property.getObjectValue();
                if (!argument.isSkippable(argument.getName())) {
                    ContentType contentType = StringUtilities.isNotEmpty(argument.getContentType())
                            ? ContentType.parse(argument.getContentType())
                            : ContentType.TEXT_PLAIN.withCharset(charset);
                    builder.addTextBody(argument.getName(), argument.getValue(), contentType);
                }
            }
            for (HTTPFileArg file : files) {
                File resolvedFile = FileServer.getFileServer().getResolvedFile(file.getPath());
                ContentType contentType = StringUtilities.isNotEmpty(file.getMimeType())
                        ? ContentType.parse(file.getMimeType()) : ContentType.DEFAULT_BINARY;
                builder.addBinaryBody(file.getParamName(), resolvedFile, contentType, file.getName());
            }
            entity = builder.build();
            requestData = getEntityPreview(entity, contentEncoding);
        } else if (!hasArguments() && getSendFileAsPostBody()) {
            HTTPFileArg file = files[0];
            if (request.getFirstHeader(HTTPConstants.HEADER_CONTENT_TYPE) == null && StringUtilities.isNotEmpty(file.getMimeType())) {
                request.setHeader(HTTPConstants.HEADER_CONTENT_TYPE, file.getMimeType());
            }
            entity = new FileEntity(FileServer.getFileServer().getResolvedFile(file.getPath()), null);
            requestData = "<actual file content, not shown here>";
        } else if (getSendParameterValuesAsPostBody()) {
            StringBuilder body = new StringBuilder();
            for (JMeterProperty property : getArguments().getEnabledArguments()) {
                body.append(((HTTPArgument) property.getObjectValue()).getEncodedValue(contentEncoding));
            }
            entity = new StringEntity(body.toString(), charset);
            requestData = body.toString();
        } else if (hasArguments()) {
            entity = new UrlEncodedFormEntity(createNameValuePairs(contentEncoding), charset);
            requestData = getEntityPreview(entity, contentEncoding);
        } else {
            return "";
        }
        request.setEntity(entity);
        return requestData;
    }

    private List<NameValuePair> createNameValuePairs(String contentEncoding) throws IOException {
        List<NameValuePair> pairs = new ArrayList<>();
        for (JMeterProperty property : getArguments().getEnabledArguments()) {
            HTTPArgument argument = (HTTPArgument) property.getObjectValue();
            String name = argument.getName();
            if (argument.isSkippable(name)) {
                continue;
            }
            String value = argument.getValue();
            if (!argument.isAlwaysEncoded()) {
                name = URLDecoder.decode(name, contentEncoding);
                value = URLDecoder.decode(value, contentEncoding);
            }
            pairs.add(new BasicNameValuePair(name, value));
        }
        return pairs;
    }

    private static String getEntityPreview(HttpEntity entity, String contentEncoding) throws IOException {
        if (!entity.isRepeatable()) {
            return "<Entity was not repeatable, cannot view what was sent>";
        }
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        entity.writeTo(output);
        return output.toString(contentEncoding);
    }

    private static void setConnectionHeaders(org.apache.hc.client5.http.classic.methods.HttpUriRequestBase request,
            HeaderManager headerManager) {
        if (headerManager == null) {
            return;
        }
        CollectionProperty headers = headerManager.getHeaders();
        if (headers == null) {
            return;
        }
        for (JMeterProperty property : headers) {
            org.apache.jmeter.protocol.http.control.Header header =
                    (org.apache.jmeter.protocol.http.control.Header) property.getObjectValue();
            if (!HTTPConstants.HEADER_CONTENT_LENGTH.equalsIgnoreCase(header.getName())) {
                request.addHeader(header.getName(), header.getValue());
            }
        }
    }

    private static String setConnectionCookie(org.apache.hc.client5.http.classic.methods.HttpUriRequestBase request,
            URL url, CookieManager cookieManager) {
        if (cookieManager == null) {
            return null;
        }
        String cookies = cookieManager.getCookieHeaderForURL(url);
        if (cookies != null) {
            request.setHeader(HTTPConstants.HEADER_COOKIE, cookies);
        }
        return cookies;
    }

    private void updateResult(ClassicHttpResponse response,
            org.apache.hc.client5.http.classic.methods.HttpUriRequestBase request, HTTPSampleResult result) throws IOException {
        result.setRequestHeaders(getRequestHeaders(request));
        Header contentType = response.getFirstHeader(HTTPConstants.HEADER_CONTENT_TYPE);
        if (contentType != null) {
            result.setContentType(contentType.getValue());
            result.setEncodingAndType(contentType.getValue());
        }
        HttpEntity entity = response.getEntity();
        long bodySize = 0;
        if (entity != null) {
            byte[] body = readResponse(result, entity.getContent(), entity.getContentLength());
            result.setResponseData(body);
            bodySize = body.length;
        }
        int statusCode = response.getCode();
        result.setResponseCode(Integer.toString(statusCode));
        result.setResponseMessage(response.getReasonPhrase());
        result.setSuccessful(isSuccessCode(statusCode));
        result.setResponseHeaders(getResponseHeaders(response));
        result.setHeadersSize(result.getResponseHeaders().length());
        result.setBodySize(bodySize);
        if (result.isRedirect()) {
            Header location = response.getFirstHeader(HTTPConstants.HEADER_LOCATION);
            if (location != null) {
                result.setRedirectLocation(location.getValue());
            }
        }
    }

    private static String getResponseHeaders(ClassicHttpResponse response) {
        StringBuilder headers = new StringBuilder();
        headers.append(response.getVersion()).append(' ').append(response.getCode()).append(' ')
                .append(response.getReasonPhrase()).append('\n');
        for (Header header : response.getHeaders()) {
            headers.append(header.getName()).append(": ").append(header.getValue()).append('\n');
        }
        return headers.toString();
    }

    private static String getRequestHeaders(org.apache.hc.client5.http.classic.methods.HttpUriRequestBase request) {
        StringBuilder headers = new StringBuilder();
        for (Header header : request.getHeaders()) {
            if (ALL_EXCEPT_COOKIE.test(header.getName())) {
                headers.append(header.getName()).append(": ").append(header.getValue()).append('\n');
            }
        }
        return headers.toString();
    }

    private static String getOnlyCookieFromHeaders(org.apache.hc.client5.http.classic.methods.HttpUriRequestBase request) {
        Header cookie = request.getFirstHeader(HTTPConstants.HEADER_COOKIE);
        return cookie == null ? "" : cookie.getValue();
    }

    private static void saveConnectionCookies(ClassicHttpResponse response, URL url, CookieManager cookieManager) {
        if (cookieManager == null) {
            return;
        }
        for (Header header : response.getHeaders(HTTPConstants.HEADER_SET_COOKIE)) {
            cookieManager.addCookieFromHeader(header.getValue(), url);
        }
    }

    private static CloseableHttpClient getClient(HttpClientKey key) {
        Map<HttpClientKey, CloseableHttpClient> clients = HTTP_CLIENTS.get();
        return clients.computeIfAbsent(key, HTTPHC5Impl::createClient);
    }

    private static CloseableHttpClient createClient(HttpClientKey key) {
        org.apache.hc.client5.http.impl.classic.HttpClientBuilder builder = HttpClients.custom().disableAutomaticRetries();
        PoolingHttpClientConnectionManagerBuilder connectionManagerBuilder = PoolingHttpClientConnectionManagerBuilder.create();
        if (key.dnsCacheManager != null) {
            connectionManagerBuilder.setDnsResolver(createDnsResolver(key.dnsCacheManager));
        }
        if (key.connectTimeout > 0) {
            connectionManagerBuilder
                    .setDefaultConnectionConfig(ConnectionConfig.custom()
                            .setConnectTimeout(Timeout.ofMilliseconds(key.connectTimeout))
                            .build());
        }
        builder.setConnectionManager(connectionManagerBuilder.build());
        builder.setRoutePlanner(new DefaultRoutePlanner(null) {
            @Override
            protected HttpHost determineProxy(HttpHost target, org.apache.hc.core5.http.protocol.HttpContext context) {
                return key.hasProxy ? new HttpHost(key.proxyScheme, key.proxyHost, key.proxyPort) : null;
            }

            @Override
            protected InetAddress determineLocalAddress(HttpHost firstHop,
                    org.apache.hc.core5.http.protocol.HttpContext context) {
                return key.localAddress;
            }
        });
        return builder.disableContentCompression()
                .addExecInterceptorFirst("response-content-encoding", RESPONSE_CONTENT_ENCODING)
                .build();
    }

    private static org.apache.hc.client5.http.DnsResolver createDnsResolver(DNSCacheManager dnsCacheManager) {
        return new org.apache.hc.client5.http.DnsResolver() {
            @Override
            public InetAddress[] resolve(String host) throws UnknownHostException {
                return dnsCacheManager.resolve(host);
            }

            @Override
            public String resolveCanonicalHostname(String host) throws UnknownHostException {
                InetAddress[] addresses = resolve(host);
                return addresses == null || addresses.length == 0 ? host : addresses[0].getCanonicalHostName();
            }
        };
    }

    private HttpClientKey createHttpClientKey(URL url) throws IOException {
        String proxyScheme = getProxyScheme();
        String proxyHost = getProxyHost();
        int proxyPort = getProxyPortInt();
        int connectTimeout = getConnectTimeout();
        DNSCacheManager dnsCacheManager = testElement.getDNSResolver();
        InetAddress localAddress = getIpSourceAddress();
        boolean useDynamicProxy = isDynamicProxy(proxyHost, proxyPort);
        boolean useStaticProxy = isStaticProxy(url.getHost());
        if (!useDynamicProxy) {
            proxyScheme = PROXY_SCHEME;
            proxyHost = PROXY_HOST;
            proxyPort = PROXY_PORT;
        }
        return new HttpClientKey(url.getProtocol(), url.getAuthority(), useDynamicProxy || useStaticProxy,
                proxyScheme, proxyHost, proxyPort, connectTimeout, dnsCacheManager, localAddress);
    }

    @Override
    protected void notifyFirstSampleAfterLoopRestart() {
        JMeterVariables variables = JMeterContextService.getContext().getVariables();
        resetStateOnThreadGroupIteration.set(variables != null && !variables.isSameUserOnNextIteration()
                && RESET_STATE_ON_THREAD_GROUP_ITERATION);
    }

    private static void resetStateIfNeeded() {
        if (resetStateOnThreadGroupIteration.get()) {
            closeThreadLocalClients();
            ((JsseSSLManager) SSLManager.getInstance()).resetContext();
            resetStateOnThreadGroupIteration.set(false);
        }
    }

    @Override
    protected void threadFinished() {
        closeThreadLocalClients();
    }

    private static void closeThreadLocalClients() {
        Map<HttpClientKey, CloseableHttpClient> clients = HTTP_CLIENTS.get();
        for (CloseableHttpClient client : clients.values()) {
            JOrphanUtils.closeQuietly(client);
        }
        clients.clear();
    }

    @Override
    public boolean interrupt() {
        org.apache.hc.client5.http.classic.methods.HttpUriRequestBase request = currentRequest;
        if (request != null) {
            currentRequest = null;
            request.cancel();
        }
        return request != null;
    }

    private static final class HttpClientKey {
        private final String protocol;
        private final String authority;
        private final boolean hasProxy;
        private final String proxyScheme;
        private final String proxyHost;
        private final int proxyPort;
        private final int connectTimeout;
        private final DNSCacheManager dnsCacheManager;
        private final InetAddress localAddress;

        private HttpClientKey(String protocol, String authority, boolean hasProxy, String proxyScheme,
                String proxyHost, int proxyPort, int connectTimeout, DNSCacheManager dnsCacheManager,
                InetAddress localAddress) {
            this.protocol = protocol;
            this.authority = authority;
            this.hasProxy = hasProxy;
            this.proxyScheme = proxyScheme;
            this.proxyHost = proxyHost;
            this.proxyPort = proxyPort;
            this.connectTimeout = connectTimeout;
            this.dnsCacheManager = dnsCacheManager;
            this.localAddress = localAddress;
        }

        @Override
        public boolean equals(Object object) {
            if (this == object) {
                return true;
            }
            if (!(object instanceof HttpClientKey other)) {
                return false;
            }
            return hasProxy == other.hasProxy && proxyPort == other.proxyPort && connectTimeout == other.connectTimeout
                    && Objects.equals(protocol, other.protocol) && Objects.equals(authority, other.authority)
                    && Objects.equals(proxyScheme, other.proxyScheme) && Objects.equals(proxyHost, other.proxyHost)
                    && Objects.equals(dnsCacheManager, other.dnsCacheManager) && Objects.equals(localAddress, other.localAddress);
        }

        @Override
        public int hashCode() {
            return Objects.hash(protocol, authority, hasProxy, proxyScheme, proxyHost, proxyPort, connectTimeout, dnsCacheManager,
                    localAddress);
        }
    }
}
