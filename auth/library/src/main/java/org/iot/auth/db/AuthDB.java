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

package org.iot.auth.db;

import org.iot.auth.AuthCrypto;
import org.iot.auth.config.AuthServerProperties;
import org.iot.auth.config.constants.C;
import org.iot.auth.db.bean.CachedSessionKeyTable;
import org.iot.auth.db.bean.MetaDataTable;
import org.iot.auth.db.bean.TrustedAuthTable;
import org.iot.auth.db.dao.SQLiteConnector;
import org.iot.auth.io.Buffer;
import org.iot.auth.server.CommunicationTargetType;
import org.iot.auth.util.ExceptionToString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.SQLException;
import java.util.*;

/**
 * A main class for Auth databases.
 * @author Hokeun Kim, Salomon Lee
 */
public class AuthDB {
    private AuthServerProperties prop = C.PROPERTIES;
    private static final Logger logger = LoggerFactory.getLogger(AuthDB.class);
    private static final String AUTH_DB_FILE_NAME = "auth.db";

    public AuthDB(String authDatabaseDir)
    {
        this.authDatabaseDir = authDatabaseDir;
        this.sqLiteConnector = new SQLiteConnector(this.authDatabaseDir + "/" + AUTH_DB_FILE_NAME);
        //sqLiteConnector.DEBUG = true;

        this.registeredEntityMap = new HashMap<>();
        this.communicationPolicyList = new ArrayList<>();
        this.trustedAuthMap = new HashMap<>();
    }

    public void initialize(String trustStorePassword) throws IOException, CertificateException,
            NoSuchAlgorithmException, KeyStoreException, SQLException, ClassNotFoundException
    {
        loadRegEntityDB();
        loadCommPolicyDB();
        loadTrustedAuthDB(trustStorePassword);
    }

    public RegisteredEntity getRegEntity(String entityName) {
        return registeredEntityMap.get(entityName);
    }

    public CommunicationPolicy getCommPolicy(String reqGroup, CommunicationTargetType targetType, String target) {
        for (CommunicationPolicy communicationPolicy : communicationPolicyList) {
            if (communicationPolicy.getReqGroup().equals(reqGroup) &&
                    communicationPolicy.getTargetType() == targetType &&
                    communicationPolicy.getTarget().equals(target)) {
                return communicationPolicy;
            }
        }
        return null;
    }

    public void updateDistributionKey(String entityName, DistributionKey distributionKey)
            throws SQLException, ClassNotFoundException
    {
        RegisteredEntity registeredEntity = getRegEntity(entityName);
        registeredEntity.setDistributionKey(distributionKey);
        registeredEntityMap.put(registeredEntity.getName(), registeredEntity);

        sqLiteConnector.updateRegEntityDistKey(entityName, distributionKey.getExpirationTime().getTime(),
                distributionKey.getKeyVal().getRawBytes());
    }

    public List<SessionKey> generateSessionKeys(int authID, String owner, int numKeys, CommunicationPolicy communicationPolicy)
            throws IOException, SQLException, ClassNotFoundException
    {
        List<SessionKey> sessionKeyList = new LinkedList<SessionKey>();

        String value = sqLiteConnector.selectMetaDataValue(MetaDataTable.key.SessionKeyCount.name());
        long sessionKeyCount = Long.parseLong(value);


        for (long i = 0; i < numKeys; i++) {
            long curSessionKeyIndex = sessionKeyCount + i;
            // TODO: work on authID encoding
            long sessionKeyID = encodeSessionKeyID(authID, curSessionKeyIndex);
            SessionKey sessionKey = new SessionKey(sessionKeyID, owner.split(SessionKey.SESSION_KEY_OWNER_NAME_DELIM),
                    new Date().getTime() + communicationPolicy.getAbsValidity(), communicationPolicy.getRelValidity(),
                    communicationPolicy.getCryptoSpec(), AuthCrypto.getRandomBytes(communicationPolicy.getCryptoSpec().getCipherKeySize()));
            sessionKeyList.add(sessionKey);
        }
        sessionKeyCount += numKeys;

        // write to _sessionKeyCountFilePath
        sqLiteConnector.updateMetaData(MetaDataTable.key.SessionKeyCount.name(), Long.toString(sessionKeyCount));

        for (SessionKey sessionKey: sessionKeyList) {
            sqLiteConnector.insertRecords(CachedSessionKeyTable.fromSessionKey(sessionKey));
        }

        return sessionKeyList;
    }

    public SessionKey getSessionKeyByID(long keyID) throws SQLException, ClassNotFoundException {
        logger.debug("keyID: {}", keyID);
        CachedSessionKeyTable cachedSessionKey = sqLiteConnector.selectCachedSessionKeyByID(keyID);
        return cachedSessionKey.toSessionKey();
    }

    public boolean addSessionKeyOwner(long keyID, String newOwner) throws SQLException, ClassNotFoundException {
        return sqLiteConnector.appendSessionKeyOwner(keyID, newOwner);
    }

    public void cleanExpiredSessionKeys() throws SQLException, ClassNotFoundException {
        sqLiteConnector.deleteExpiredCahcedSessionKeys();
    }

    public TrustedAuth getTrustedAuthInfo(int authID) {
        return trustedAuthMap.get(authID);
    }

    public String sessionKeysToString() throws SQLException, ClassNotFoundException {
        StringBuilder sb = new StringBuilder();

        List<CachedSessionKeyTable> cachedSessionKeyList = sqLiteConnector.selectAllCachedSessionKey();
        boolean init = true;
        for (CachedSessionKeyTable cachedSessionKey: cachedSessionKeyList) {
            if (init) {
                init = false;
            }
            else {
                sb.append("\n");
            }
            sb.append(cachedSessionKey.toSessionKey().toString());
        }
        return sb.toString();
    }

    public String regEntitiesToString() {
        StringBuilder sb = new StringBuilder();
        boolean init = true;
        for (RegisteredEntity registeredEntity : registeredEntityMap.values()) {
            if (init) {
                init = false;
            }
            else {
                sb.append("\n");
            }
            sb.append(registeredEntity.toString());
        }
        return sb.toString();
    }

    public String commPoliciesToString() {
        StringBuilder sb = new StringBuilder();
        boolean init = true;
        for (CommunicationPolicy communicationPolicy : communicationPolicyList) {
            if (init) {
                init = false;
            }
            else {
                sb.append("\n");
            }
            sb.append(communicationPolicy.toString());
        }
        return sb.toString();
    }

    public String trustedAuthsToString() {
        StringBuilder sb = new StringBuilder();
        boolean init = true;
        for (TrustedAuth trustedAuth: trustedAuthMap.values()) {
            if (init) {
                init = false;
            }
            else {
                sb.append("\n");
            }
            sb.append(trustedAuth.toBriefString());
        }
        return sb.toString();
    }

    public int getTrustedAuthIDByCert(X509Certificate cert) {
        try {
            String alias = trustStoreForTrustedAuths.getCertificateAlias(cert);
            return Integer.parseInt(alias);
        } catch (KeyStoreException e) {
            logger.error("KeyStoreException {}", ExceptionToString.convertExceptionToStackTrace(e));
            throw new RuntimeException("Unrecognized trusted Auth certificate!");
        }
    }

    private void loadRegEntityDB() throws SQLException, ClassNotFoundException {
        sqLiteConnector.selectAllRegEntities(authDatabaseDir).forEach(regEntityTable -> {
            RegisteredEntity registeredEntity = new RegisteredEntity(
                    regEntityTable.getName(),
                    regEntityTable.getGroup(),
                    regEntityTable.getPublicKey(),
                    regEntityTable.getDistKeyValidity(),
                    SymmetricKeyCryptoSpec.fromJSSpec(regEntityTable.getDistCipherAlgo(), regEntityTable.getDistHashAlgo())
            );
            if (regEntityTable.getDistKeyVal() != null) {
                registeredEntity.setDistributionKey(new DistributionKey(new Buffer(regEntityTable.getDistKeyVal()),
                        regEntityTable.getDistKeyExpirationTime()));
            }
            registeredEntityMap.put(registeredEntity.getName(), registeredEntity);
            logger.debug("registeredEntity: {}", registeredEntity.toString());
        });
    }

    private void loadCommPolicyDB() throws SQLException, ClassNotFoundException {
        sqLiteConnector.selectAllPolicies().forEach(c -> {
            CommunicationPolicy communicationPolicy = new CommunicationPolicy(c.getReqGroup(), c.getTargetType(), c.getTarget(),
                    c.getCipherAlgo(), c.getHashAlgo(),
                    c.getAbsValidity(), c.getRelValidity());
            communicationPolicyList.add(communicationPolicy);
            logger.debug("communicationPolicy: {}", communicationPolicy.toString());
        });
    }

    private void loadTrustedAuthDB(String trustStorePassword) throws
            KeyStoreException, CertificateException, NoSuchAlgorithmException, SQLException, ClassNotFoundException, IOException
    {
        // TODO: replace this with password input
        trustStoreForTrustedAuths = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStoreForTrustedAuths.load(null, trustStorePassword.toCharArray());

        for (TrustedAuthTable t: sqLiteConnector.selectAllTrustedAuth()) {
            TrustedAuth trustedAuth = new TrustedAuth(t.getId(), t.getHost(),
                    t.getPort(),
                    AuthCrypto.loadCertificate(t.getCertificatePath()));
            trustedAuthMap.put(trustedAuth.getID(), trustedAuth);
            // TODO: Add trust store for trusted auth
            trustStoreForTrustedAuths.setCertificateEntry("" + trustedAuth.getID(), trustedAuth.getCertificate());

            logger.debug("trustedAuth: {}", trustedAuth.toString());
        }
    }

    public static long encodeSessionKeyID(int authID, long keyIndex) {
        return authID * 100000 + keyIndex;
    };
    public static int decodeAuthIDFromSessionKeyID(long sessionKeyID) {
        return (int)(sessionKeyID / 100000);
    };

    private String authDatabaseDir;

    private Map<String, RegisteredEntity> registeredEntityMap;
    private List<CommunicationPolicy> communicationPolicyList;
    private Map<Integer, TrustedAuth> trustedAuthMap;
    private KeyStore trustStoreForTrustedAuths;

    private SQLiteConnector sqLiteConnector;
}