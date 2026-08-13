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

import java.net.InetAddress;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Base64;

import javax.security.auth.Subject;

import org.apache.jmeter.protocol.http.control.AuthManager;
import org.apache.jmeter.protocol.http.util.HTTPConstants;
import org.apache.jmeter.util.JMeterUtils;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import okhttp3.Authenticator;
import okhttp3.HttpUrl;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.Route;

/**
 * {@link Authenticator} implementing the SPNEGO (Kerberos) scheme for the OkHttp based sampler.
 * <p>
 * OkHttp has no built-in support for negotiation based auth schemes, so the {@code Negotiate}
 * challenge of a {@code 401} response is answered here with a GSS token which is built from the
 * JAAS {@link Subject} of the HTTP Authorization Manager.
 * </p>
 * @since 6.0
 */
final class SpnegoAuthenticator implements Authenticator {

    private static final Logger log = LoggerFactory.getLogger(SpnegoAuthenticator.class);

    /** Builds the GSS token with the credentials of the current JAAS context. */
    static final TokenGenerator DEFAULT_TOKEN_GENERATOR = SpnegoAuthenticator::createGssToken;

    static final SpnegoAuthenticator INSTANCE = new SpnegoAuthenticator();

    static final String NEGOTIATE = "Negotiate";

    private static final String WWW_AUTHENTICATE = "WWW-Authenticate";

    private static final Oid SPNEGO_OID = createOid("1.3.6.1.5.5.2");

    private static final boolean DELEGATE_CRED = JMeterUtils.getPropDefault("kerberos.spnego.delegate_cred", false);

    private final TokenGenerator tokenGenerator;

    private SpnegoAuthenticator() {
        this(DEFAULT_TOKEN_GENERATOR);
    }

    SpnegoAuthenticator(TokenGenerator tokenGenerator) {
        this.tokenGenerator = tokenGenerator;
    }

    /**
     * Creates the GSS token for the given service principal name and the (possibly empty) token of
     * the server.
     */
    @FunctionalInterface
    interface TokenGenerator {
        byte[] createToken(String authServer, byte[] input) throws GSSException;
    }

    /**
     * Kerberos data of the sampler which is attached to a request, so that the challenge of the
     * server can be answered with the credentials of the matching authorization.
     */
    static final class KerberosContext {
        private final Subject subject;
        private final boolean stripPort;

        KerberosContext(Subject subject, URL url) {
            this(subject, isStripPort(url.getPort()));
        }

        KerberosContext(Subject subject, boolean stripPort) {
            this.subject = subject;
            this.stripPort = stripPort;
        }
    }

    /**
     * IE and Firefox always strip the port from the URL before constructing the SPN, so the port
     * is stripped as well, unless the JMeter property <code>kerberos.spnego.strip_port</code> asks
     * for a port in the SPN of non default ports.
     */
    static boolean isStripPort(int port) {
        if (AuthManager.STRIP_PORT) {
            return true;
        }
        return port == HTTPConstants.DEFAULT_HTTP_PORT || port == HTTPConstants.DEFAULT_HTTPS_PORT;
    }

    @Override
    public Request authenticate(Route route, Response response) {
        Request request = response.request();
        KerberosContext kerberosContext = request.tag(KerberosContext.class);
        if (kerberosContext == null) {
            return null;
        }
        String existingAuthorization = request.header(HTTPConstants.HEADER_AUTHORIZATION);
        if (existingAuthorization != null) {
            if (existingAuthorization.regionMatches(true, 0, NEGOTIATE, 0, NEGOTIATE.length())) {
                log.warn("The server rejected the SPNEGO token for {}, giving up", request.url());
            } else {
                log.debug("The request for {} is already authorized, no SPNEGO token is added", request.url());
            }
            return null;
        }
        String challenge = getNegotiateChallenge(response);
        if (challenge == null) {
            log.debug("Server did not offer the {} scheme for {}", NEGOTIATE, request.url());
            return null;
        }
        String token = generateToken(kerberosContext, request.url(), decodeChallenge(challenge));        if (token == null) {
            return null;
        }
        return request.newBuilder()
                .header(HTTPConstants.HEADER_AUTHORIZATION, NEGOTIATE + " " + token)
                .build();
    }

    /**
     * @return the (possibly empty) token of the {@code Negotiate} challenge of the response, or
     *         {@code null} if the server did not ask for {@code Negotiate} authentication
     */
    static String getNegotiateChallenge(Response response) {
        return getNegotiateChallenge(response, WWW_AUTHENTICATE);
    }

    /**
     * @param headerName {@value #WWW_AUTHENTICATE} for a server, {@code Proxy-Authenticate} for a proxy
     * @return the (possibly empty) token of the {@code Negotiate} challenge of the response, or
     *         {@code null} if the challenge did not offer {@code Negotiate} authentication
     */
    static String getNegotiateChallenge(Response response, String headerName) {
        for (String header : response.headers(headerName)) {
            String trimmedHeader = header.trim();
            if (!trimmedHeader.regionMatches(true, 0, NEGOTIATE, 0, NEGOTIATE.length())) {
                continue;
            }
            String remainder = trimmedHeader.substring(NEGOTIATE.length());
            if (!remainder.isEmpty() && !Character.isWhitespace(remainder.charAt(0))
                    && remainder.charAt(0) != ',') {
                // another scheme whose name starts with "Negotiate"
                continue;
            }
            // a single header may offer several schemes, like "Negotiate, NTLM"
            int endOfToken = remainder.indexOf(',');
            return (endOfToken < 0 ? remainder : remainder.substring(0, endOfToken)).trim();
        }
        return null;
    }

    private static byte[] decodeChallenge(String challenge) {
        if (challenge.isEmpty()) {
            return new byte[0];
        }
        try {
            return Base64.getDecoder().decode(challenge);
        } catch (IllegalArgumentException e) {
            log.warn("Could not decode the {} challenge {}, continuing without an input token",
                    NEGOTIATE, challenge, e);
            return new byte[0];
        }
    }

    private String generateToken(KerberosContext kerberosContext, HttpUrl url, byte[] input) {
        return generateToken(tokenGenerator, kerberosContext.subject,
                getAuthServer(url, kerberosContext.stripPort), input);
    }

    /**
     * Builds the base 64 encoded SPNEGO token for the given service principal name, with the
     * credentials of the given JAAS {@link Subject}, or with the credentials of the current
     * context if no subject is available.
     *
     * @return the token, or {@code null} if it could not be created
     */
    static String generateToken(TokenGenerator tokenGenerator, Subject subject, String authServer, byte[] input) {
        if (SPNEGO_OID == null) {
            return null;
        }
        try {
            byte[] token = subject == null
                    ? tokenGenerator.createToken(authServer, input)
                    : Subject.doAs(subject,
                            (PrivilegedExceptionAction<byte[]>) () -> tokenGenerator.createToken(authServer, input));
            return token == null ? null : Base64.getEncoder().encodeToString(token);
        } catch (PrivilegedActionException e) {
            log.warn("Could not create a SPNEGO token for {}", authServer, e.getException());
        } catch (GSSException e) {
            log.warn("Could not create a SPNEGO token for {}", authServer, e);
        }
        return null;
    }

    /**
     * Builds the base 64 encoded SPNEGO token for the {@code Negotiate} challenge of a response.
     *
     * @return the token, or {@code null} if it could not be created
     */
    static String generateToken(TokenGenerator tokenGenerator, Subject subject, String authServer,
            String challenge) {
        return generateToken(tokenGenerator, subject, authServer, decodeChallenge(challenge));
    }

    private static byte[] createGssToken(String authServer, byte[] input) throws GSSException {
        GSSManager manager = GSSManager.getInstance();
        GSSName serverName = manager.createName("HTTP@" + authServer, GSSName.NT_HOSTBASED_SERVICE);
        GSSCredential credential = manager.createCredential(null, GSSCredential.DEFAULT_LIFETIME,
                SPNEGO_OID, GSSCredential.INITIATE_ONLY);
        GSSContext context = manager.createContext(serverName.canonicalize(SPNEGO_OID), SPNEGO_OID,
                credential, GSSContext.DEFAULT_LIFETIME);
        context.requestMutualAuth(true);
        context.requestCredDeleg(DELEGATE_CRED);
        try {
            return context.initSecContext(input, 0, input.length);
        } finally {
            context.dispose();
        }
    }

    static String getAuthServer(HttpUrl url, boolean stripPort) {
        return getAuthServer(url.host(), url.port(), stripPort);
    }

    static String getAuthServer(String host, int port, boolean stripPort) {
        String authServer = host;
        if (AuthManager.USE_CANONICAL_HOST_NAME) {
            authServer = getCanonicalHostName(authServer);
        }
        return stripPort ? authServer : authServer + ":" + port;
    }

    private static String getCanonicalHostName(String host) {
        try {
            return InetAddress.getByName(host).getCanonicalHostName();
        } catch (UnknownHostException e) {
            log.debug("Could not resolve the canonical host name of {}, using it as is", host, e);
            return host;
        }
    }

    private static Oid createOid(String oid) {
        try {
            return new Oid(oid);
        } catch (GSSException e) {
            log.warn("Could not create OID {}", oid, e);
            return null;
        }
    }
}
