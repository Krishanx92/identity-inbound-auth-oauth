/*
 * Copyright (c) 2013, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth;

import org.apache.commons.io.Charsets;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.utils.Base64;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCacheKey;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.registry.core.utils.UUIDGenerator;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public final class OAuthUtil {

    public static final Log log = LogFactory.getLog(OAuthUtil.class);
    private static final String ALGORITHM = "HmacSHA1";

    private OAuthUtil() {

    }

    /**
     * Generates a random number using two UUIDs and HMAC-SHA1
     *
     * @return generated secure random number
     * @throws IdentityOAuthAdminException Invalid Algorithm or Invalid Key
     */
    public static String getRandomNumber() throws IdentityOAuthAdminException {
        try {
            String secretKey = UUIDGenerator.generateUUID();
            String baseString = UUIDGenerator.generateUUID();

            SecretKeySpec key = new SecretKeySpec(secretKey.getBytes(Charsets.UTF_8), ALGORITHM);
            Mac mac = Mac.getInstance(ALGORITHM);
            mac.init(key);
            byte[] rawHmac = mac.doFinal(baseString.getBytes(Charsets.UTF_8));
            String random = Base64.encode(rawHmac);
            // Registry doesn't have support for these character.
            random = random.replace("/", "_");
            random = random.replace("=", "a");
            random = random.replace("+", "f");
            return random;
        } catch (Exception e) {
            throw new IdentityOAuthAdminException("Error when generating a random number.", e);
        }
    }

    public static void clearOAuthCache(String consumerKey, User authorizedUser) {

        clearOAuthCache(consumerKey, getFullyQualifiedUserName(authorizedUser));
    }

    public static void clearOAuthCache(String consumerKey, User authorizedUser, String scope) {

        clearOAuthCache(consumerKey, getFullyQualifiedUserName(authorizedUser), scope);
    }

    public static void clearOAuthCache(String consumerKey, String authorizedUser) {
        boolean isUsernameCaseSensitive = IdentityUtil.isUserStoreInUsernameCaseSensitive(authorizedUser);
        if (!isUsernameCaseSensitive) {
            authorizedUser = authorizedUser.toLowerCase();
        }
        clearOAuthCache(consumerKey + ":" + authorizedUser);
    }

    public static void clearOAuthCache(String consumerKey, String authorizedUser, String scope) {
        boolean isUsernameCaseSensitive = IdentityUtil.isUserStoreInUsernameCaseSensitive(authorizedUser);
        if (!isUsernameCaseSensitive) {
            authorizedUser = authorizedUser.toLowerCase();
        }
        clearOAuthCache(consumerKey + ":" + authorizedUser + ":" + scope);
    }

    public static void clearOAuthCache(String oauthCacheKey) {

        OAuthCacheKey cacheKey = new OAuthCacheKey(oauthCacheKey);
        OAuthCache.getInstance().clearCacheEntry(cacheKey);
    }

    public static void clearOAuthCacheByAccessToken(String accessToken) throws IdentityOAuth2Exception {

        // For token types such a JWT access tokens we do not store the original access token in the DB/cache. We store
        // an alias of the original token (eg: jti claim of the JWT) instead. Therefore when clearing the cache we need
        // to derive the alias and clear the cache. For normal UUID tokens the alias is the original token itself.
        String persistedTokenIdentifier = OAuth2Util.getAccessTokenIdentifier(accessToken);
        clearOAuthCache(persistedTokenIdentifier);
    }

    public static AuthenticatedUser getAuthenticatedUser(String fullyQualifiedUserName) {

        if (StringUtils.isBlank(fullyQualifiedUserName)) {
            throw new RuntimeException("Invalid username.");
        }

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserStoreDomain(IdentityUtil.extractDomainFromName(fullyQualifiedUserName));
        authenticatedUser.setTenantDomain(MultitenantUtils.getTenantDomain(fullyQualifiedUserName));

        String username = fullyQualifiedUserName;
        if (fullyQualifiedUserName.startsWith(authenticatedUser.getUserStoreDomain())) {
            username = UserCoreUtil.removeDomainFromName(fullyQualifiedUserName);
        }
        authenticatedUser.setUserName(MultitenantUtils.getTenantAwareUsername(username));

        return authenticatedUser;
    }

    /**
     * This is used to handle the OAuthAdminService exceptions. This will log the error message and return an
     * IdentityOAuthAdminException exception
     * @param message error message
     * @param exception Exception.
     * @return
     */
    public static IdentityOAuthAdminException handleError(String message, Exception exception) {
        log.error(message);
        if (exception == null) {
            return new IdentityOAuthAdminException(message);
        } else {
            if (log.isDebugEnabled()) {
                log.debug(exception);
            }
            return new IdentityOAuthAdminException(message, exception);
        }
    }

    /**
     * Get the fully qualified username of the user.
     *
     * @param user User object.
     * @return Fully qualified username of the user.
     */
    public static String getFullyQualifiedUserName(User user) {

        if (!OAuthServerConfiguration.getInstance().isMapFederatedUsersToLocal() && user instanceof AuthenticatedUser &&
                ((AuthenticatedUser) user).isFederatedUser()) {
            if (log.isDebugEnabled()) {
                log.debug("User is federated and not mapped to local users. Hence adding 'FEDERATED' domain will be " +
                        "added to to the full qualified username.");
            }
            AuthenticatedUser federatedUser = (AuthenticatedUser) user;
            String authUser = federatedUser.getUserName();
            if (StringUtils.isBlank(authUser)) {
                // Username may be null for federated users.
                authUser = federatedUser.getAuthenticatedSubjectIdentifier();
            }
            if (StringUtils.isNotBlank(authUser)) {
                authUser = UserCoreUtil.addDomainToName(authUser, OAuth2Util.getFederatedUserDomain
                        (federatedUser.getFederatedIdPName()));
                if (StringUtils.isNotBlank(federatedUser.getTenantDomain())) {
                    authUser = UserCoreUtil.addTenantDomainToEntry(authUser, federatedUser.getTenantDomain());
                }
            }
            return authUser;
        } else {
            return user.toString();
        }
    }
}
