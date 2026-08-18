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

import java.io.File;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.Proxy;
import java.net.Socket;
import java.net.URL;
import java.nio.charset.Charset;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.WeakHashMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.zip.Inflater;

import javax.net.SocketFactory;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.Subject;

import org.apache.jmeter.protocol.http.control.AuthManager;
import org.apache.jmeter.protocol.http.control.Authorization;
import org.apache.jmeter.protocol.http.control.CacheManager;
import org.apache.jmeter.protocol.http.control.CookieManager;
import org.apache.jmeter.protocol.http.control.DNSCacheManager;
import org.apache.jmeter.protocol.http.control.Header;
import org.apache.jmeter.protocol.http.control.HeaderManager;
import org.apache.jmeter.protocol.http.util.HTTPArgument;
import org.apache.jmeter.protocol.http.util.HTTPConstants;
import org.apache.jmeter.protocol.http.util.HTTPFileArg;
import org.apache.jmeter.services.FileServer;
import org.apache.jmeter.testelement.property.CollectionProperty;
import org.apache.jmeter.testelement.property.JMeterProperty;
import org.apache.jmeter.threads.JMeterContextService;
import org.apache.jmeter.threads.JMeterVariables;
import org.apache.jmeter.util.HttpSSLProtocolSocketFactory;
import org.apache.jmeter.util.JMeterUtils;
import org.apache.jmeter.util.JsseSSLManager;
import org.apache.jmeter.util.SSLManager;
import org.apache.jorphan.io.CountingInputStream;
import org.apache.jorphan.util.JOrphanUtils;
import org.apache.jorphan.util.StringUtilities;
import org.brotli.dec.BrotliInputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import okhttp3.Call;
import okhttp3.Connection;
import okhttp3.ConnectionPool;
import okhttp3.EventListener;
import okhttp3.FormBody;
import okhttp3.Handshake;
import okhttp3.Headers;
import okhttp3.HttpUrl;
import okhttp3.Interceptor;
import okhttp3.MediaType;
import okhttp3.MultipartBody;
import okhttp3.OkHttp;
import okhttp3.OkHttpClient;
import okhttp3.Protocol;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;
import okio.Buffer;
import okio.BufferedSink;
import okio.BufferedSource;
import okio.ByteString;
import okio.GzipSource;
import okio.InflaterSource;
import okio.Okio;
import okio.Source;

/**
 * HTTP Sampler using OkHttp 5.x.
 */
public class HTTPOkImpl extends HTTPHCAbstractImpl {

    private static final Logger log = LoggerFactory.getLogger(HTTPOkImpl.class);

    private static final ThreadLocal<Map<HttpClientKey, OkHttpClient>> HTTP_CLIENTS =
            new InheritableThreadLocal<>() {
                @Override
                protected Map<HttpClientKey, OkHttpClient> initialValue() {
                    return new ConcurrentHashMap<>();
                }
            };

    private static final String DISABLE_DEFAULT_UA_PROPERTY = "okhttp.default_user_agent_disabled";

    private static final String RETRY_ON_CONNECTION_FAILURE_PROPERTY = "okhttp.retry_on_connection_failure";

    private static final String STALE_CONNECTION_RETRIES_PROPERTY = "okhttp.stale_connection_retries";

    /**
     * Maximum number of idle connections OkHttp keeps per client. JMeter uses a client per thread
     * and target, and the parallel downloads of the embedded resources of a page share it, so the
     * OkHttp default of {@code 5} is one short of the six parallel downloads JMeter defaults to.
     */
    private static final int MAX_IDLE_CONNECTIONS =
            JMeterUtils.getPropDefault("okhttp.max_idle_connections", 6);

    /**
     * Milliseconds an unused connection is kept in the pool. Aligning it with the keep alive
     * timeout of the server (or of a load balancer in between) avoids handing out connections the
     * peer has closed in the meantime.
     */
    private static final long IDLE_CONNECTION_TIMEOUT =
            JMeterUtils.getPropDefault("okhttp.idle_connection_timeout", 300_000L);

    private static final String DEFAULT_USER_AGENT = "OkHttp/" + OkHttp.VERSION;

    private static final boolean HTTP_2_PRIOR_KNOWLEDGE =
            JMeterUtils.getPropDefault("okhttp.h2.prior_knowledge", false);

    private static final X509TrustManager TRUST_ALL_MANAGER = new X509TrustManager() {
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    };

    /**
     * Connections which already carried a response. A connection only gets here after the peer
     * answered on it, so a failure on one of them means that the connection was reused, and that
     * the peer closed it in the meantime.
     */
    private static final Set<Connection> USED_CONNECTIONS =
            Collections.synchronizedSet(Collections.newSetFromMap(new WeakHashMap<>()));

    private static final EventListener SAMPLE_EVENT_LISTENER = new SampleEventListener();

    /**
     * Feeds the sample result with the data OkHttp only exposes while the call is running: the
     * moment a connection is established and the number of bytes the request occupies on the wire.
     */
    private static final class SampleEventListener extends EventListener {
        @Override
        public void connectionAcquired(Call call, Connection connection) {
            ConnectionReuseTracker tracker = call.request().tag(ConnectionReuseTracker.class);
            if (tracker != null) {
                tracker.connectionAcquired(connection);
            }
        }

        @Override
        public void responseHeadersEnd(Call call, Response response) {
            ConnectionReuseTracker tracker = call.request().tag(ConnectionReuseTracker.class);
            Connection connection = tracker == null ? null : tracker.getConnection();
            if (connection != null) {
                USED_CONNECTIONS.add(connection);
            }
        }

        @Override
        public void connectEnd(Call call, InetSocketAddress inetSocketAddress, Proxy proxy, Protocol protocol) {
            recordConnectEnd(call);
        }

        @Override
        public void requestHeadersEnd(Call call, Request request) {
            SentBytesTracker tracker = call.request().tag(SentBytesTracker.class);
            if (tracker != null) {
                // The request of the event carries the headers OkHttp added on its own, such as
                // Host, Content-Length, Connection and Accept-Encoding
                tracker.addSentBytes(calculateRequestHeaderBytes(request));
            }
        }

        @Override
        public void requestBodyEnd(Call call, long byteCount) {
            SentBytesTracker tracker = call.request().tag(SentBytesTracker.class);
            if (tracker != null) {
                tracker.addSentBytes(byteCount);
            }
        }

        @Override
        public void secureConnectEnd(Call call, Handshake handshake) {
            recordConnectEnd(call);
        }

        private static void recordConnectEnd(Call call) {
            HTTPSampleResult sample = call.request().tag(HTTPSampleResult.class);
            if (sample != null) {
                sample.connectEnd();
            }
        }
    }

    /**
     * Repeats a request that failed on a connection which had already carried a response, that is
     * on a connection which was reused. OkHttp only checks a pooled connection for a close of the
     * peer when the request is not a {@code GET}, so a keep alive connection the server (or a load
     * balancer in between) closed while the thread was busy elsewhere is used as it is, and the
     * sample fails with {@code unexpected end of stream}. That is an artifact of the connection
     * pool rather than server behavior, so the request is sent again on a fresh connection, which
     * is what {@code retryOnConnectionFailure} would do if the transparent retries were not
     * disabled. Failures on a connection that never carried a response, timeouts and protocol
     * errors are never repeated, so a server that refuses or drops new connections keeps failing
     * the sample. As a pool can hold several connections the peer closed, the request is repeated
     * up to {@code okhttp.stale_connection_retries} times, each attempt discarding the connection
     * it failed on.
     */
    private static final Interceptor STALE_CONNECTION_RETRY_INTERCEPTOR = chain -> {
        Request request = chain.request();
        ConnectionReuseTracker tracker = request.tag(ConnectionReuseTracker.class);
        int attempt = 0;
        while (true) {
            if (tracker != null) {
                tracker.reset();
            }
            try {
                return chain.proceed(request);
            } catch (IOException e) {
                attempt++;
                if (attempt > getStaleConnectionRetries() || !isRepeatableOnANewConnection(chain, tracker, e)) {
                    throw e;
                }
                // Every attempt discards the connection it failed on, so a pool full of connections
                // the peer closed while the thread was idle is drained request by request
                log.debug("Repeating {} on another connection, the reused connection was closed by the peer",
                        request.url(), e);
            }
        }
    };

    private static boolean isRepeatableOnANewConnection(Interceptor.Chain chain, ConnectionReuseTracker tracker,
            IOException failure) {
        if (tracker == null || chain.call().isCanceled()) {
            return false;
        }
        if (!isStaleConnectionFailure(failure)) {
            log.debug("Not repeating {}, the failure is not a closed connection", chain.request().url(), failure);
            return false;
        }
        Connection connection = tracker.getConnection();
        if (connection == null || !USED_CONNECTIONS.contains(connection)) {
            log.debug("Not repeating {}, the connection which failed did not carry a response before",
                    chain.request().url(), failure);
            return false;
        }
        return true;
    }

    private static final Interceptor DECOMPRESSION_INTERCEPTOR = chain -> {
        Response response = chain.proceed(chain.request());
        ResponseBody body = response.body();
        if (body == null) {
            return response;
        }
        String encoding = response.header(HTTPConstants.HEADER_CONTENT_ENCODING);
        if (encoding == null) {
            return response;
        }
        encoding = encoding.toLowerCase(Locale.ROOT);
        boolean gzip = "gzip".equals(encoding) || "x-gzip".equals(encoding);
        boolean deflate = "deflate".equals(encoding);
        boolean brotli = "br".equals(encoding);
        if (!gzip && !deflate && !brotli) {
            return response;
        }
        // The bytes are counted before they are decoded, so the sample result reports the size the
        // response had on the wire, like the HttpClient and the Java based implementations do
        CountingInputStream wireBytes = new CountingInputStream(body.byteStream());
        Source decoded;
        if (gzip) {
            decoded = new GzipSource(Okio.buffer(Okio.source(wireBytes)));
        } else if (deflate) {
            decoded = new InflaterSource(Okio.buffer(Okio.source(wireBytes)), new Inflater(true));
        } else {
            decoded = Okio.source(new BrotliInputStream(wireBytes));
        }
        return response.newBuilder()
                .body(new CountingResponseBody(Okio.buffer(decoded), body.contentType(), wireBytes))
                .build();
    };

    private volatile Call currentCall;

    protected HTTPOkImpl(HTTPSamplerBase testElement) {
        super(testElement);
    }

    @Override
    protected HTTPSampleResult sample(URL url, String method, boolean areFollowingRedirect, int frameDepth) {
        HTTPSampleResult result = createSampleResult(url, method);
        Request request = null;
        Response response = null;
        try {
            resetStateIfNeeded();
            Request.Builder requestBuilder = new Request.Builder();
            setupRequest(url, method, requestBuilder, result);
            request = requestBuilder.build();
            if (StringUtilities.isEmpty(result.getCookies())) {
                // the Header Manager may carry the cookies when no Cookie Manager handles them
                result.setCookies(getOnlyCookieFromHeaders(headersOf(request.headers())));
            }
            result.sampleStart();

            CacheManager cacheManager = getCacheManager();
            if (cacheManager != null && HTTPConstants.GET.equalsIgnoreCase(method)) {
                Header[] requestHeaders = getRequestHeadersArray(getHeaderManager());
                if (cacheManager.inCache(url, requestHeaders)) {
                    return updateSampleResultForResourceInCache(result);
                }
            }

            HttpClientKey clientKey = createHttpClientKey(url);
            OkHttpClient client = getClient(clientKey);

            Call call = client.newCall(request);
            currentCall = call;
            SpnegoProxyAuthenticator.setSubject(getSubjectForProxy(clientKey));
            try {
                response = call.execute();
            } finally {
                SpnegoProxyAuthenticator.clearSubject();
            }
            readResponse(response, result);
            result.sampleEnd();
            currentCall = null;

            updateResult(response, response.request(), result);
            if (cacheManager != null) {
                cacheManager.saveDetails(response::header, result);
            }
            saveConnectionCookies(response, result.getURL(), getCookieManager());
            return resultProcessing(areFollowingRedirect, frameDepth, result);
        } catch (Exception e) {
            if (result.getEndTime() == 0) {
                result.sampleEnd();
            }
            if (request != null) {
                result.setRequestHeaders(getRequestHeaders(request));
                result.setSentBytes(getSentBytes(request));
            }
            return errorResult(e, result);
        } finally {
            JOrphanUtils.closeQuietly(response);
            currentCall = null;
        }
    }

    /**
     * @return the JAAS {@link Subject} of the Kerberos entry the HTTP Authorization Manager holds
     *         for the proxy, or {@code null} if the proxy is not covered by such an entry, in
     *         which case a {@code Negotiate} challenge of the proxy is answered with the Kerberos
     *         ticket of the JMeter user
     */
    Subject getSubjectForProxy(HttpClientKey key) {
        AuthManager authManager = getAuthManager();
        URL proxyUrl = getProxyUrl(key);
        return authManager == null || proxyUrl == null ? null : authManager.getSubjectForUrl(proxyUrl);
    }

    private static URL getProxyUrl(HttpClientKey key) {
        if (!key.hasProxy) {
            return null;
        }
        String scheme = StringUtilities.isEmpty(key.proxyScheme) ? HTTPConstants.PROTOCOL_HTTP : key.proxyScheme;
        try {
            return new URL(scheme, key.proxyHost, key.proxyPort, "");
        } catch (MalformedURLException e) {
            log.debug("Could not build a URL for proxy {}://{}:{}", scheme, key.proxyHost, key.proxyPort, e);
            return null;
        }
    }

    private HTTPSampleResult createSampleResult(URL url, String method) {        HTTPSampleResult result = new HTTPSampleResult();
        configureSampleLabel(result, url);
        result.setHTTPMethod(method);
        result.setURL(url);
        return result;
    }

    private void setupRequest(URL url, String method, Request.Builder requestBuilder,
            HTTPSampleResult result) throws IOException {
        requestBuilder.url(url);
        requestBuilder.tag(HTTPSampleResult.class, result);
        requestBuilder.tag(ConnectionReuseTracker.class, new ConnectionReuseTracker());
        requestBuilder.tag(SentBytesTracker.class, new SentBytesTracker());

        setConnectionHeaders(requestBuilder, url, getHeaderManager());
        setDefaultUserAgent(requestBuilder);

        CacheManager cacheManager = getCacheManager();
        if (cacheManager != null) {
            Header[] requestHeaders = getRequestHeadersArray(getHeaderManager());
            cacheManager.setHeaders(url, CacheManager.requestHeaderSink(
                    cacheRequestHeaders(requestHeaders), requestBuilder::header));
        }

        String cookies = setConnectionCookie(url, getCookieManager(), requestBuilder::header);
        if (StringUtilities.isNotEmpty(cookies)) {
            result.setCookies(cookies);
        }

        AuthManager authManager = getAuthManager();
        Authorization authorization = authManager == null ? null : authManager.getAuthForURL(url);
        if (authorization != null) {
            setupAuthorization(url, requestBuilder, authManager, authorization);
        }

        RequestBody body = null;
        if (canHaveBody(method)) {
            body = createRequestBody(result);
        }
        requestBuilder.method(method, body);
    }

    /**
     * Applies the authorization of the HTTP Authorization Manager to the request. {@code BASIC}
     * credentials are sent preemptively, while the {@code KERBEROS} mechanism needs a challenge of
     * the server, so its data is attached to the request for {@link SpnegoAuthenticator}.
     */
    @SuppressWarnings("deprecation") // Mechanism.BASIC_DIGEST is kept for backwards compatibility
    static void setupAuthorization(URL url, Request.Builder requestBuilder, AuthManager authManager,
            Authorization authorization) {
        AuthManager.Mechanism mechanism = authorization.getMechanism();
        if (AuthManager.Mechanism.KERBEROS.equals(mechanism)) {
            requestBuilder.tag(SpnegoAuthenticator.KerberosContext.class,
                    new SpnegoAuthenticator.KerberosContext(authManager.getSubjectForUrl(url), url));
        } else if (AuthManager.Mechanism.BASIC.equals(mechanism)
                || AuthManager.Mechanism.BASIC_DIGEST.equals(mechanism)) {
            requestBuilder.header(HTTPConstants.HEADER_AUTHORIZATION, authorization.toBasicHeader());
        } else {
            log.warn("The {} implementation does not support the {} authorization mechanism for {}",
                    HTTPSamplerFactory.IMPL_OK_HTTP, mechanism, url);
        }
    }

    private static boolean canHaveBody(String method) {
        return HTTPConstants.POST.equalsIgnoreCase(method) || HTTPConstants.PUT.equalsIgnoreCase(method)
                || HTTPConstants.PATCH.equalsIgnoreCase(method) || HTTPConstants.DELETE.equalsIgnoreCase(method);
    }

    private RequestBody createRequestBody(HTTPSampleResult result) throws IOException {
        HTTPFileArg[] files = getHTTPFiles();
        String contentEncoding = getContentEncoding();
        Charset charset = StringUtilities.isNotEmpty(contentEncoding) ? Charset.forName(contentEncoding)
                : Charset.defaultCharset();
        RequestBody requestBody;
        String requestData;

        if (getUseMultipart()) {
            MultipartBody.Builder builder = new MultipartBody.Builder().setType(MultipartBody.FORM);
            for (JMeterProperty property : getArguments().getEnabledArguments()) {
                HTTPArgument argument = (HTTPArgument) property.getObjectValue();
                if (!argument.isSkippable(argument.getName())) {
                    String name = argument.getName();
                    String value = argument.getValue();
                    builder.addFormDataPart(name, value);
                }
            }
            List<ViewableFileBody> fileBodies = new ArrayList<>(files.length);
            for (HTTPFileArg file : files) {
                File resolvedFile = FileServer.getFileServer().getResolvedFile(file.getPath());
                MediaType mediaType = StringUtilities.isNotEmpty(file.getMimeType())
                        ? MediaType.parse(file.getMimeType()) : MediaType.parse("application/octet-stream");
                ViewableFileBody fileBody = new ViewableFileBody(resolvedFile, mediaType);
                fileBodies.add(fileBody);
                builder.addFormDataPart(file.getParamName(), file.getName(), fileBody);
            }
            MultipartBody multipartBody = builder.build();
            requestBody = multipartBody;
            requestData = getMultipartPreview(multipartBody, fileBodies, charset);
        } else if (!hasArguments() && getSendFileAsPostBody()) {
            HTTPFileArg file = files[0];
            MediaType mediaType = StringUtilities.isNotEmpty(file.getMimeType())
                    ? MediaType.parse(file.getMimeType()) : null;
            requestBody = RequestBody.create(FileServer.getFileServer().getResolvedFile(file.getPath()), mediaType);
            requestData = "<actual file content, not shown here>";
        } else if (getSendParameterValuesAsPostBody()) {
            StringBuilder body = new StringBuilder();
            for (JMeterProperty property : getArguments().getEnabledArguments()) {
                body.append(((HTTPArgument) property.getObjectValue()).getEncodedValue(contentEncoding));
            }
            requestBody = RequestBody.create(body.toString(), null);
            requestData = body.toString();
        } else if (hasArguments()) {
            FormBody.Builder builder = new FormBody.Builder(charset);
            forEachFormParameter(charset.name(), builder::add);
            FormBody formBody = builder.build();
            requestBody = formBody;
            requestData = getEntityPreview(formBody, charset);
        } else {
            requestBody = RequestBody.create(new byte[0], null);
            requestData = "";
        }
        result.setQueryString(requestData);
        return requestBody;
    }

    private static String getEntityPreview(RequestBody body, Charset charset) throws IOException {
        Buffer buffer = new Buffer();
        body.writeTo(buffer);
        return buffer.readString(charset);
    }

    /**
     * Renders the multipart body for the request view without the content of the uploaded files.
     * The files are streamed from disk when the request is sent, so writing them into the preview
     * would be the only point where an upload is materialized in memory, which fails for a file
     * that does not fit into the heap.
     *
     * @param body the multipart body that is sent
     * @param fileBodies the parts that carry a file, they are asked to omit their content
     * @param charset charset the preview is decoded with
     * @return the multipart body with the file contents replaced by a placeholder
     * @throws IOException if the body cannot be written
     */
    private static String getMultipartPreview(MultipartBody body, List<ViewableFileBody> fileBodies, Charset charset)
            throws IOException {
        fileBodies.forEach(fileBody -> fileBody.hideFileData = true);
        try {
            return getEntityPreview(body, charset);
        } finally {
            fileBodies.forEach(fileBody -> fileBody.hideFileData = false);
        }
    }

    /**
     * Decoded response body which remembers how many bytes were read from the network before they
     * were decompressed, so the sample result can report the size the response had on the wire
     * instead of the size it expanded to.
     */
    private static final class CountingResponseBody extends ResponseBody {
        private final BufferedSource source;
        private final MediaType contentType;
        private final CountingInputStream wireBytes;

        private CountingResponseBody(BufferedSource source, MediaType contentType,
                CountingInputStream wireBytes) {
            this.source = source;
            this.contentType = contentType;
            this.wireBytes = wireBytes;
        }

        @Override
        public MediaType contentType() {
            return contentType;
        }

        @Override
        public long contentLength() {
            // The decoded length is unknown until the body has been read
            return -1L;
        }

        @Override
        public BufferedSource source() {
            return source;
        }

        private long getBytesRead() {
            return wireBytes.getBytesRead();
        }
    }

    /**
     * File upload that can write a placeholder instead of the content of the file, so that the
     * request view can be built without reading the file into memory. The announced content length
     * is always the length of the file, as the body is only rendered with the placeholder while the
     * preview is generated, never while the request is sent.
     */
    private static final class ViewableFileBody extends RequestBody {
        private static final ByteString CONTENTS_OMITTED =
                ByteString.encodeUtf8("<actual file content, not shown here>");

        private final File file;
        private final MediaType mediaType;
        private boolean hideFileData;

        private ViewableFileBody(File file, MediaType mediaType) {
            this.file = file;
            this.mediaType = mediaType;
        }

        @Override
        public MediaType contentType() {
            return mediaType;
        }

        @Override
        public long contentLength() {
            return file.length();
        }

        @Override
        public void writeTo(BufferedSink sink) throws IOException {
            if (hideFileData) {
                sink.write(CONTENTS_OMITTED);
                return;
            }
            try (Source source = Okio.source(file)) {
                sink.writeAll(source);
            }
        }
    }

    private static Header[] getRequestHeadersArray(HeaderManager headerManager) {
        if (headerManager == null) {
            return new Header[0];
        }
        CollectionProperty headers = headerManager.getHeaders();
        if (headers == null) {
            return new Header[0];
        }
        Header[] result = new Header[headers.size()];
        int i = 0;
        for (JMeterProperty property : headers) {
            result[i++] = (Header) property.getObjectValue();
        }
        return result;
    }

    /**
     * Adapts the headers a request will be sent with to the client neutral view used by
     * {@link CacheManager}.
     *
     * @param headers headers of the request
     * @return view of the request headers
     */
    private static CacheManager.RequestHeaderSource cacheRequestHeaders(Header[] headers) {
        return action -> {
            for (Header header : headers) {
                action.accept(header.getName(), header.getValue());
            }
        };
    }

    private static void setConnectionHeaders(Request.Builder requestBuilder, URL url, HeaderManager headerManager) {
        setConnectionHeaders(headerManager, url, name -> true, requestBuilder::addHeader);
    }

    /**
     * Adapts the headers of a request or a response to the representation the helpers of
     * {@link HTTPHCAbstractImpl} work on.
     *
     * @param headers headers of the request or the response
     * @return the headers of the message
     */
    private static HeaderIterable headersOf(Headers headers) {
        return action -> {
            for (int i = 0; i < headers.size(); i++) {
                action.accept(headers.name(i), headers.value(i));
            }
        };
    }

    private static void setDefaultUserAgent(Request.Builder requestBuilder) {
        if (isDefaultUserAgentDisabled()) {
            return;
        }
        requestBuilder.header("User-Agent", DEFAULT_USER_AGENT);
    }

    private void readResponse(Response response, HTTPSampleResult result) throws IOException {
        String contentType = response.header(HTTPConstants.HEADER_CONTENT_TYPE);
        if (contentType != null) {
            result.setContentType(contentType);
            result.setEncodingAndType(contentType);
        }
        ResponseBody body = response.body();
        if (body != null) {
            if (body instanceof CountingResponseBody countingBody) {
                // The compressed bytes were already counted before the body was decoded
                byte[] responseData = readResponse(result, body.byteStream(), body.contentLength());
                result.setResponseData(responseData);
                result.setBodySize(countingBody.getBytesRead());
            } else {
                // The stored response is truncated when httpsampler.max_bytes_to_store_per_request is
                // set, so the body is counted while it is read to report what the server actually sent
                CountingInputStream countingStream = new CountingInputStream(body.byteStream());
                byte[] responseData = readResponse(result, countingStream, body.contentLength());
                result.setResponseData(responseData);
                result.setBodySize(countingStream.getBytesRead());
            }
        }
    }

    private void updateResult(Response response, Request request, HTTPSampleResult result) {
        result.setRequestHeaders(getRequestHeaders(request));
        result.setSentBytes(getSentBytes(request));
        int statusCode = response.code();
        result.setResponseCode(Integer.toString(statusCode));
        result.setResponseMessage(response.message());
        result.setSuccessful(isSuccessCode(statusCode));
        result.setResponseHeaders(getResponseHeaders(response));
        // Approximated the way HTTPHC4Impl does it, so all implementations report the same size:
        // the condensed headers (without \r), a \r per header, a \r for the status line and the
        // final \r\n before the body
        long headerBytes =
                (long) result.getResponseHeaders().length()
                + response.headers().size()
                + 1L
                + 2L;
        result.setHeadersSize((int) headerBytes);
        if (response.priorResponse() != null) {
            // OkHttp followed the redirects on its own, so the response was sampled from the URL of
            // the last request. The cookie and the cache manager as well as the listeners need it.
            result.setURL(request.url().url());
        }
        if (result.isRedirect()) {
            String location = response.header(HTTPConstants.HEADER_LOCATION);
            if (location == null) { // HTTP protocol violation, but avoids NPE
                throw new IllegalArgumentException(
                        "Missing location header in redirect for " + request.method() + " " + request.url());
            }
            result.setRedirectLocation(location);
        }
    }

    private static String getResponseHeaders(Response response) {
        StringBuilder headers = new StringBuilder();
        headers.append(formatProtocol(response.protocol())).append(' ').append(response.code()).append(' ')
                .append(response.message()).append('\n');
        headers.append(formatHeaders(headersOf(response.headers()), name -> true));
        return headers.toString();
    }

    private static String formatProtocol(Protocol protocol) {
        if (protocol == Protocol.HTTP_2 || protocol == Protocol.H2_PRIOR_KNOWLEDGE) {
            return HTTPConstants.HTTP_VERSION_2;
        }
        return HTTPConstants.HTTP_VERSION_1_1;
    }

    private static String getRequestHeaders(Request request) {
        return formatHeaders(headersOf(request.headers()), ALL_EXCEPT_COOKIE);
    }

    /**
     * @param request request of the sample, may be {@code null} if it could not be built
     * @return the bytes the call wrote on the wire, including every attempt of a redirect or of an
     *         authentication challenge. If nothing was sent, for instance because the connection
     *         failed, the request that was about to be sent is measured instead
     */
    private static long getSentBytes(Request request) {
        if (request == null) {
            return 0;
        }
        SentBytesTracker tracker = request.tag(SentBytesTracker.class);
        long sentBytes = tracker == null ? 0 : tracker.getSentBytes();
        return sentBytes > 0 ? sentBytes : calculateSentBytes(request);
    }

    private static long calculateSentBytes(Request request) {
        if (request == null) {
            return 0;
        }
        return calculateRequestHeaderBytes(request) + calculateRequestBodyBytes(request);
    }

    private static long calculateRequestHeaderBytes(Request request) {
        HttpUrl url = request.url();
        String pathAndQuery = url.encodedPath() + (url.encodedQuery() != null ? "?" + url.encodedQuery() : "");
        long sentBytes = HTTPMessageSizes.requestLineLength(request.method(), pathAndQuery, HTTPConstants.HTTP_1_1);

        Headers headers = request.headers();
        for (int i = 0; i < headers.size(); i++) {
            sentBytes += HTTPMessageSizes.headerLength(headers.name(i), headers.value(i));
        }
        sentBytes += HTTPMessageSizes.EMPTY_LINE;
        return sentBytes;
    }

    private static long calculateRequestBodyBytes(Request request) {
        RequestBody body = request.body();
        if (body == null) {
            return 0;
        }
        try {
            // The body is never written into a buffer here, as an upload is streamed from disk and
            // may not fit into the heap. A body of unknown length is only reported by the tracker
            long contentLength = body.contentLength();
            return Math.max(contentLength, 0);
        } catch (IOException e) {
            log.debug("Exception measuring request body length", e);
            return 0;
        }
    }

    private static void saveConnectionCookies(Response response, URL url, CookieManager cookieManager) {
        saveConnectionCookies(headersOf(response.headers()), url, cookieManager);
    }

    private static OkHttpClient getClient(HttpClientKey key) {
        Map<HttpClientKey, OkHttpClient> clients = HTTP_CLIENTS.get();
        return clients.computeIfAbsent(key, HTTPOkImpl::createClient);
    }

    private static boolean isDefaultUserAgentDisabled() {
        return JMeterUtils.getPropDefault(DISABLE_DEFAULT_UA_PROPERTY, false);
    }

    private static boolean isRetryOnConnectionFailureEnabled() {
        return JMeterUtils.getPropDefault(RETRY_ON_CONNECTION_FAILURE_PROPERTY, false);
    }

    private static int getStaleConnectionRetries() {
        // Every attempt discards the connection it failed on, so a pool full of connections the
        // peer closed needs as many attempts as the pool can hold
        return JMeterUtils.getPropDefault(STALE_CONNECTION_RETRIES_PROPERTY, MAX_IDLE_CONNECTIONS);
    }

    /**
     * @return whether {@code e} is the kind of failure a connection which the peer closed while it
     *         was idle in the pool produces. Read timeouts and protocol violations are answers of
     *         the server (or of the network) and have to fail the sample.
     */
    private static boolean isStaleConnectionFailure(IOException e) {
        return !(e instanceof InterruptedIOException) && !(e instanceof ProtocolException);
    }

    /**
     * Remembers the connection a call is using, which tells a failure of a reused connection apart
     * from a failure of a connection that has never carried a response.
     */
    static final class ConnectionReuseTracker {
        private final AtomicReference<Connection> connection = new AtomicReference<>();

        void reset() {
            connection.set(null);
        }

        void connectionAcquired(Connection acquired) {
            connection.set(acquired);
        }

        Connection getConnection() {
            return connection.get();
        }
    }

    /**
     * Sums the bytes a call wrote on the wire. The request headers are measured when OkHttp has
     * assembled them, so the headers it adds on its own are counted, and the body is reported by
     * OkHttp once it has been written, so a streamed file upload counts with its real size instead
     * of the placeholder the request view shows. A call that is repeated, for instance to follow a
     * redirect or to answer a challenge, adds up every attempt.
     */
    static final class SentBytesTracker {
        private final AtomicLong sentBytes = new AtomicLong();

        void addSentBytes(long bytes) {
            if (bytes > 0) {
                sentBytes.addAndGet(bytes);
            }
        }

        long getSentBytes() {
            return sentBytes.get();
        }
    }

    static OkHttpClient createClient(HttpClientKey key) {
        OkHttpClient.Builder builder = new OkHttpClient.Builder();
        builder.addInterceptor(STALE_CONNECTION_RETRY_INTERCEPTOR);
        builder.addInterceptor(DECOMPRESSION_INTERCEPTOR);
        builder.eventListener(SAMPLE_EVENT_LISTENER);
        builder.connectionPool(
                new ConnectionPool(MAX_IDLE_CONNECTIONS, IDLE_CONNECTION_TIMEOUT, TimeUnit.MILLISECONDS));
        builder.followRedirects(key.autoRedirects);
        builder.followSslRedirects(key.autoRedirects);
        // JMeter must report what the server actually did, so by default transparent retries of
        // failed connections (and of 408 responses) are disabled, just like disableAutomaticRetries()
        // in the HttpClient based implementations.
        builder.retryOnConnectionFailure(isRetryOnConnectionFailureEnabled());
        // OkHttp has no built-in support for negotiation based auth schemes, so the SPNEGO
        // (Kerberos) challenges of the HTTP Authorization Manager are answered here
        builder.authenticator(SpnegoAuthenticator.INSTANCE);

        if (key.connectTimeout > 0) {
            builder.connectTimeout(key.connectTimeout, TimeUnit.MILLISECONDS);
        }
        if (key.responseTimeout > 0) {
            builder.readTimeout(key.responseTimeout, TimeUnit.MILLISECONDS);
        }

        builder.protocols(key.protocols);

        SSLSocketFactory sslSocketFactory = new HttpSSLProtocolSocketFactory(JsseSSLManager.CPS);
        if (key.localAddress != null) {
            builder.socketFactory(new LocalAddressSocketFactory(key.localAddress));
            sslSocketFactory = new LocalAddressSSLSocketFactory(sslSocketFactory, key.localAddress);
        }
        builder.sslSocketFactory(sslSocketFactory, TRUST_ALL_MANAGER);
        builder.hostnameVerifier((hostname, session) -> true);

        if (key.dnsCacheManager != null) {
            builder.dns(hostname -> {
                InetAddress[] addresses = key.dnsCacheManager.resolve(hostname);
                return addresses != null ? Arrays.asList(addresses) : okhttp3.Dns.SYSTEM.lookup(hostname);
            });
        }

        if (key.hasProxy) {
            Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(key.proxyHost, key.proxyPort));
            builder.proxy(proxy);
            // OkHttp has no built-in support for negotiation based auth schemes, so a
            // "Proxy-Authenticate: Negotiate" challenge of an enterprise proxy is answered with a
            // SPNEGO token, while a "Basic" challenge is answered with the configured credentials
            builder.proxyAuthenticator(
                    new SpnegoProxyAuthenticator(key.proxyHost, key.proxyPort, key.proxyUser, key.proxyPass));
        }

        return builder.build();
    }

    HttpClientKey createHttpClientKey(URL url) throws IOException {
        String proxyScheme = getProxyScheme();
        String proxyHost = getProxyHost();
        int proxyPort = getProxyPortInt();
        int connectTimeout = getConnectTimeout();
        int responseTimeout = getResponseTimeout();
        String proxyUser = getProxyUser();
        String proxyPass = getProxyPass();
        DNSCacheManager dnsCacheManager = testElement.getDNSResolver();
        InetAddress localAddress = getIpSourceAddress();
        boolean useDynamicProxy = isDynamicProxy(proxyHost, proxyPort);
        boolean useStaticProxy = isStaticProxy(url.getHost());
        List<Protocol> protocols = getProtocols(testElement.getHttpVersion(), DEFAULT_HTTP_VERSION,
                url.getProtocol());
        if (!useDynamicProxy) {
            proxyScheme = PROXY_SCHEME;
            proxyHost = PROXY_HOST;
            proxyPort = PROXY_PORT;
        }
        return new HttpClientKey(url.getProtocol(), url.getAuthority(), useDynamicProxy || useStaticProxy,
                proxyScheme, proxyHost, proxyPort, proxyUser, proxyPass, connectTimeout, responseTimeout,
                getAutoRedirects(), dnsCacheManager, localAddress, protocols);
    }

    static List<Protocol> getProtocols(String samplerHttpVersion, String defaultHttpVersion, String scheme) {
        String httpVersion = StringUtilities.isBlank(samplerHttpVersion) ? defaultHttpVersion : samplerHttpVersion;
        // OkHttp negotiates the protocol, so a strict HTTP/2 request is negotiated as well
        if (HTTPConstants.HTTP_VERSION_2.equalsIgnoreCase(httpVersion)
                || HTTPConstants.HTTP_VERSION_2_STRICT.equalsIgnoreCase(httpVersion)) {
            if (HTTP_2_PRIOR_KNOWLEDGE && !HTTPConstants.PROTOCOL_HTTPS.equalsIgnoreCase(scheme)) {
                return List.of(Protocol.H2_PRIOR_KNOWLEDGE);
            }
            return List.of(Protocol.HTTP_2, Protocol.HTTP_1_1);
        }
        return List.of(Protocol.HTTP_1_1);
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
        Map<HttpClientKey, OkHttpClient> clients = HTTP_CLIENTS.get();
        for (OkHttpClient client : clients.values()) {
            client.dispatcher().executorService().shutdown();
            client.connectionPool().evictAll();
        }
        clients.clear();
    }

    @Override
    public boolean interrupt() {
        Call call = currentCall;
        if (call != null) {
            currentCall = null;
            call.cancel();
        }
        return call != null;
    }

    private static final class LocalAddressSocketFactory extends SocketFactory {
        private final InetAddress localAddress;

        LocalAddressSocketFactory(InetAddress localAddress) {
            this.localAddress = localAddress;
        }

        @Override
        public Socket createSocket() throws IOException {
            Socket socket = new Socket();
            socket.bind(new InetSocketAddress(localAddress, 0));
            return socket;
        }

        @Override
        public Socket createSocket(String host, int port) throws IOException {
            Socket socket = new Socket();
            socket.bind(new InetSocketAddress(localAddress, 0));
            socket.connect(new InetSocketAddress(host, port));
            return socket;
        }

        @Override
        public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException {
            Socket socket = new Socket();
            socket.bind(new InetSocketAddress(this.localAddress, 0));
            socket.connect(new InetSocketAddress(host, port));
            return socket;
        }

        @Override
        public Socket createSocket(InetAddress host, int port) throws IOException {
            Socket socket = new Socket();
            socket.bind(new InetSocketAddress(localAddress, 0));
            socket.connect(new InetSocketAddress(host, port));
            return socket;
        }

        @Override
        public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
            Socket socket = new Socket();
            socket.bind(new InetSocketAddress(this.localAddress, 0));
            socket.connect(new InetSocketAddress(address, port));
            return socket;
        }
    }

    private static final class LocalAddressSSLSocketFactory extends SSLSocketFactory {
        private final SSLSocketFactory delegate;
        private final InetAddress localAddress;

        LocalAddressSSLSocketFactory(SSLSocketFactory delegate, InetAddress localAddress) {
            this.delegate = delegate;
            this.localAddress = localAddress;
        }

        @Override
        public Socket createSocket() throws IOException {
            Socket socket = new Socket();
            socket.bind(new InetSocketAddress(localAddress, 0));
            return delegate.createSocket(socket, null, 0, true);
        }

        @Override
        public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
            if (!s.isBound()) {
                s.bind(new InetSocketAddress(localAddress, 0));
            }
            return delegate.createSocket(s, host, port, autoClose);
        }

        @Override
        public Socket createSocket(String host, int port) throws IOException {
            Socket socket = new Socket();
            socket.bind(new InetSocketAddress(localAddress, 0));
            socket.connect(new InetSocketAddress(host, port));
            return delegate.createSocket(socket, host, port, true);
        }

        @Override
        public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException {
            Socket socket = new Socket();
            socket.bind(new InetSocketAddress(this.localAddress, 0));
            socket.connect(new InetSocketAddress(host, port));
            return delegate.createSocket(socket, host, port, true);
        }

        @Override
        public Socket createSocket(InetAddress host, int port) throws IOException {
            Socket socket = new Socket();
            socket.bind(new InetSocketAddress(localAddress, 0));
            socket.connect(new InetSocketAddress(host, port));
            return delegate.createSocket(socket, host.getHostAddress(), port, true);
        }

        @Override
        public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
            Socket socket = new Socket();
            socket.bind(new InetSocketAddress(this.localAddress, 0));
            socket.connect(new InetSocketAddress(address, port));
            return delegate.createSocket(socket, address.getHostAddress(), port, true);
        }

        @Override
        public String[] getDefaultCipherSuites() {
            return delegate.getDefaultCipherSuites();
        }

        @Override
        public String[] getSupportedCipherSuites() {
            return delegate.getSupportedCipherSuites();
        }
    }

    static final class HttpClientKey {
        private final String protocol;
        private final String authority;
        private final boolean hasProxy;
        private final String proxyScheme;
        private final String proxyHost;
        private final int proxyPort;
        private final String proxyUser;
        private final String proxyPass;
        private final int connectTimeout;
        private final int responseTimeout;
        private final boolean autoRedirects;
        private final DNSCacheManager dnsCacheManager;
        private final InetAddress localAddress;
        private final List<Protocol> protocols;

        private HttpClientKey(String protocol, String authority, boolean hasProxy, String proxyScheme,
                String proxyHost, int proxyPort, String proxyUser, String proxyPass, int connectTimeout,
                int responseTimeout, boolean autoRedirects, DNSCacheManager dnsCacheManager,
                InetAddress localAddress, List<Protocol> protocols) {
            this.protocol = protocol;
            this.authority = authority;
            this.hasProxy = hasProxy;
            this.proxyScheme = proxyScheme;
            this.proxyHost = proxyHost;
            this.proxyPort = proxyPort;
            this.proxyUser = proxyUser;
            this.proxyPass = proxyPass;
            this.connectTimeout = connectTimeout;
            this.responseTimeout = responseTimeout;
            this.autoRedirects = autoRedirects;
            this.dnsCacheManager = dnsCacheManager;
            this.localAddress = localAddress;
            this.protocols = protocols;
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
                    && responseTimeout == other.responseTimeout && autoRedirects == other.autoRedirects
                    && Objects.equals(protocol, other.protocol) && Objects.equals(authority, other.authority)
                    && Objects.equals(proxyScheme, other.proxyScheme) && Objects.equals(proxyHost, other.proxyHost)
                    && Objects.equals(proxyUser, other.proxyUser) && Objects.equals(proxyPass, other.proxyPass)
                    && Objects.equals(dnsCacheManager, other.dnsCacheManager) && Objects.equals(localAddress, other.localAddress)
                    && Objects.equals(protocols, other.protocols);
        }

        @Override
        public int hashCode() {
            return Objects.hash(protocol, authority, hasProxy, proxyScheme, proxyHost, proxyPort, proxyUser, proxyPass,
                    connectTimeout, responseTimeout, autoRedirects, dnsCacheManager, localAddress, protocols);
        }
    }
}
