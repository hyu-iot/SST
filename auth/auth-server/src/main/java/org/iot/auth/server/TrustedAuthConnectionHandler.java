/*
 * Copyright (c) 2016, Regents of the University of California
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * IOTAUTH_COPYRIGHT_VERSION_1
 */

package org.iot.auth.server;

import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.iot.auth.AuthServer;
import org.iot.auth.db.SessionKey;
import org.iot.auth.db.SessionKeyPurpose;
import org.iot.auth.db.TrustedAuth;
import org.iot.auth.message.AuthSessionKeyReqMessage;
import org.iot.auth.message.AuthSessionKeyRespMessage;
import org.iot.auth.util.ExceptionToString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/**
 * A handler class for connections from other trusted Auths
 * @author Hokeun Kim
 */
public class TrustedAuthConnectionHandler extends AbstractHandler {

    /**
     * Constructor for the trusted connection handler
     * @param server Auth server that this handler works for
     */
    public TrustedAuthConnectionHandler(AuthServer server) {
        this.server = server;
    }


    /**
     * This method implements the handle method of AbstractHandler interface, for handling a HTTP request.
     * @param target The target of HTTP request (url or name), NOT used in this handler.
     * @param baseRequest The original unwrapped request object, mainly used in this handler.
     * @param request Request of the wrapper, only used for getting the certificate of the requester (a trusted Auth) in
     *                this handler.
     * @param response The response to be sent to the requester (trusted Auth).
     * @throws IOException If any IO fails.
     * @throws ServletException
     */
    public void handle( String target, Request baseRequest, HttpServletRequest request,
                        HttpServletResponse response) throws IOException, ServletException
    {
        logger.info("Handler reached!, request from: {}:{}",
                baseRequest.getRemoteHost(), baseRequest.getRemotePort());

        X509Certificate[] certs = (X509Certificate[])request.getAttribute("javax.servlet.request.X509Certificate");
        // Alias == ID
        int requestingAuthID = server.getTrustedAuthIDByCertificate(certs[0]);
        logger.info("Alias: {} ", requestingAuthID);

        // TODO: Check client (trusted Auth) identity before sending response
        TrustedAuth requestingAuthInfo = server.getTrustedAuthInfo(requestingAuthID);

        if (requestingAuthInfo == null) {
            throw new RuntimeException("Unrecognized Auth");
        }

        logger.info("Requesting Auth info: {}", requestingAuthInfo.toBriefString());

        AuthSessionKeyReqMessage authSessionKeyReqMessage = AuthSessionKeyReqMessage.fromHttpRequest(baseRequest);
        logger.info("Received AuthSessionKeyReqMessage: {}", authSessionKeyReqMessage.toString());

        List<SessionKey> sessionKeyList = null;
        if (authSessionKeyReqMessage.getCachedKeyAuthID() > 0) {
            if (server.getAuthID() != authSessionKeyReqMessage.getCachedKeyAuthID()) {
                throw new RuntimeException("Auth ID is not my ID!");
            }
            SessionKeyPurpose purpose = new SessionKeyPurpose(CommunicationTargetType.TARGET_GROUP, authSessionKeyReqMessage.getRequestingEntityGroup());
            try {
                sessionKeyList = server.getSessionKeysByPurpose(authSessionKeyReqMessage.getRequestingEntityName(), purpose);
            } catch (SQLException | ClassNotFoundException e) {
                logger.error("SQLException | ClassNotFoundException {}", ExceptionToString.convertExceptionToStackTrace(e));
                throw new RuntimeException("Exception occurred while finding cached session keys.");
            }
            try {
                for (SessionKey sessionKey : sessionKeyList) {
                    server.addSessionKeyOwner(sessionKey.getID(), authSessionKeyReqMessage.getRequestingEntityName());
                }
            } catch (SQLException | ClassNotFoundException e) {
                logger.error("SQLException | ClassNotFoundException {}", ExceptionToString.convertExceptionToStackTrace(e));
                throw new RuntimeException("Exception occurred while adding session key owner for cached session keys.");
            }
        }
        else {
            SessionKey sessionKey;
            try {
                sessionKey = server.getSessionKeyByID(authSessionKeyReqMessage.getSessionKeyID());
            } catch (SQLException | ClassNotFoundException e) {
                logger.error("SQLException | ClassNotFoundException {}", ExceptionToString.convertExceptionToStackTrace(e));
                throw new RuntimeException("Session key for ID " + authSessionKeyReqMessage.getSessionKeyID() + " cannot be found!");
            }

            try {
                server.addSessionKeyOwner(authSessionKeyReqMessage.getSessionKeyID(), authSessionKeyReqMessage.getRequestingEntityName());
            } catch (SQLException | ClassNotFoundException e) {
                logger.error("SQLException | ClassNotFoundException {}", ExceptionToString.convertExceptionToStackTrace(e));
                throw new RuntimeException("Exception occurred while adding session key owner.");
            }
            // TODO: Check group requirement
            sessionKeyList = new ArrayList<>();
            sessionKeyList.add(sessionKey);
        }

        AuthSessionKeyRespMessage authSessionKeyRespMessage = new AuthSessionKeyRespMessage(sessionKeyList);
        authSessionKeyRespMessage.sendAsHttpResponse(response);

        // Inform jetty that this request has now been handled
        baseRequest.setHandled(true);
    }

    private AuthServer server;
    private static final Logger logger = LoggerFactory.getLogger(TrustedAuthConnectionHandler.class);
}
