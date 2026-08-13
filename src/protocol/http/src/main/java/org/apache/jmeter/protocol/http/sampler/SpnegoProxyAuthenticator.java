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

import javax.security.auth.Subject;

import org.apache.jorphan.util.StringUtilities;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import okhttp3.Authenticator;
import okhttp3.Credentials;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.Route;

/**
 * {@link Authenticator} answering the {@code 407 Proxy Authentication Required} challenges of a
 * proxy for the OkHttp based sampler.
 * <p>
 * Enterprise proxies commonly challenge with {@code Proxy-Authenticate: Negotiate}, which OkHttp
 * does not support out of the box, so the challenge is answered here with a SPNEGO (Kerberos)
 * token. A {@code Basic} challenge is answered with the proxy user and password of the sampler, as
 * before. A proxy which offers {@code Negotiate} while the sampler has a proxy user configured
 * keeps using the password based scheme, unless the HTTP Authorization Manager holds a Kerberos
 * entry for the proxy.
 * </p>
 * @since 6.0
 */
final class SpnegoProxyAuthenticator implements Authenticator {

    private static final Logger log = LoggerFactory.getLogger(SpnegoProxyAuthenticator.class);

    private static final String PROXY_AUTHENTICATE = "Proxy-Authenticate";

    private static final String PROXY_AUTHORIZATION = "Proxy-Authorization";

    /**
     * The JAAS {@link Subject} of the Kerberos entry the HTTP Authorization Manager holds for the
     * proxy, if any. The clients are cached per proxy configuration and shared by all samplers of
     * a thread, and the request of a proxy tunnel ({@code CONNECT}) is created by OkHttp itself,
     * so the subject cannot be attached to the request. As the sampler executes its call on the
     * current thread, the subject is passed to the authenticator in a thread local instead.
     */
    private static final ThreadLocal<Subject> PROXY_SUBJECT = new ThreadLocal<>();

    private final String proxyHost;
    private final int proxyPort;
    private final String proxyUser;
    private final String proxyPass;
    private final SpnegoAuthenticator.TokenGenerator tokenGenerator;

    SpnegoProxyAuthenticator(String proxyHost, int proxyPort, String proxyUser, String proxyPass) {
        this(proxyHost, proxyPort, proxyUser, proxyPass, SpnegoAuthenticator.DEFAULT_TOKEN_GENERATOR);
    }

    SpnegoProxyAuthenticator(String proxyHost, int proxyPort, String proxyUser, String proxyPass,
            SpnegoAuthenticator.TokenGenerator tokenGenerator) {
        this.proxyHost = proxyHost;
        this.proxyPort = proxyPort;
        this.proxyUser = proxyUser;
        this.proxyPass = proxyPass;
        this.tokenGenerator = tokenGenerator;
    }

    /**
     * Publishes the JAAS {@link Subject} to authenticate with at the proxy for the calls of the
     * current thread. It has to be removed with {@link #clearSubject()} once the call is done.
     */
    static void setSubject(Subject subject) {
        if (subject == null) {
            PROXY_SUBJECT.remove();
        } else {
            PROXY_SUBJECT.set(subject);
        }
    }

    static void clearSubject() {
        PROXY_SUBJECT.remove();
    }

    @Override
    public Request authenticate(Route route, Response response) {
        Request request = response.request();
        if (request.header(PROXY_AUTHORIZATION) != null) {
            log.debug("The proxy rejected the credentials for {}, giving up", request.url());
            return null; // give up after one attempt
        }
        String credential = createCredential(response, request);
        if (credential == null) {
            return null;
        }
        return request.newBuilder().header(PROXY_AUTHORIZATION, credential).build();
    }

    private String createCredential(Response response, Request request) {
        String challenge = SpnegoAuthenticator.getNegotiateChallenge(response, PROXY_AUTHENTICATE);
        boolean hasPassword = StringUtilities.isNotEmpty(proxyUser);
        Subject subject = PROXY_SUBJECT.get();
        if (challenge != null && (!hasPassword || subject != null)) {
            String authServer = SpnegoAuthenticator.getAuthServer(proxyHost, proxyPort,
                    SpnegoAuthenticator.isStripPort(proxyPort));
            String token = SpnegoAuthenticator.generateToken(tokenGenerator, subject, authServer, challenge);
            if (token != null) {
                return SpnegoAuthenticator.NEGOTIATE + " " + token;
            }
        }
        if (!hasPassword) {
            log.debug("The proxy asked for authentication for {}, but no proxy credentials are configured "
                    + "and no Kerberos ticket is available", request.url());
            return null;
        }
        return Credentials.basic(proxyUser, proxyPass);
    }
}
