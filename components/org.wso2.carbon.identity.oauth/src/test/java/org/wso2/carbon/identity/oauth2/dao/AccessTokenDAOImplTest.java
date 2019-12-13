/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.dao;

import org.mockito.Mock;
import org.mockito.Mockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.LocalAndOutboundAuthenticationConfig;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.AppInfoCache;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.dao.SQLQueries;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth.tokenprocessor.PlainTextPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.dao.util.DAOConstants;
import org.wso2.carbon.identity.oauth2.dao.util.DAOUtils;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.token.JWTTokenIssuer;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuer;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuerImpl;
import org.wso2.carbon.identity.testutil.IdentityBaseTest;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Timestamp;
import java.util.UUID;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.spy;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertEquals;
import static org.wso2.carbon.identity.oauth2.dao.util.DAOConstants.CALLBACK_URL;
import static org.wso2.carbon.identity.oauth2.dao.util.DAOConstants.FRAMEWORK_PERSISTENCE_POOL_SIZE;
import static org.wso2.carbon.identity.oauth2.dao.util.DAOConstants.OAUTH_TOKEN_PERSISTENCE_POOL_SIZE;
import static org.wso2.carbon.identity.oauth2.dao.util.DAOConstants.OAUTH_TOKEN_PERSISTENCE_RETRY_COUNT;
import static org.wso2.carbon.identity.oauth2.dao.util.DAOConstants.SAMPLE_TENANT_DOMAIN;
import static org.wso2.carbon.identity.oauth2.dao.util.DAOConstants.SAMPLE_TENANT_ID;
import static org.wso2.carbon.identity.oauth2.dao.util.DAOConstants.VALID_SCOPE_1;

/**
 * This class tests the functionality of the AccessTokenDAOImpl class
 */
@WithCarbonHome
@PrepareForTest({IdentityDatabaseUtil.class, IdentityUtil.class, OAuthServerConfiguration.class, AppInfoCache.class})
public class AccessTokenDAOImplTest extends IdentityBaseTest {

    private static final String DB_NAME = "TOKEN_DB";
    private static final Long DEFAULT_TOKEN_VALIDITY_TIME = 3600L;
    private static final String JWT_TOKEN = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9" +
            ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsIm" +
            "p0aSI6ImQzNWRmMTRkLTA5ZjYtNDhmZi04YTkzLTdjNmYwMzM5MzE1OSIsImlhdCI6MTU0M" +
            "Tk3MTU4MywiZXhwIjoxNTQxOTc1MTgzfQ.QaQOarmV8xEUYV7yvWzX3cUE_4W1luMcWCwpr" +
            "oqqUrg";

    private AccessTokenDAO accessTokenDAO;

    @Mock
    private OAuthServerConfiguration mockedOAuthServerConfiguration;

    @Mock
    private RealmService mockedRealmService;

    @Mock
    private ApplicationManagementService mockedApplicationManagementService;

    @Mock
    private TenantManager mockedTenantManager;

    @Mock
    private ServiceProvider mockedServiceProvider;

    @Mock
    private LocalAndOutboundAuthenticationConfig mockedLocalAndOutboundAuthenticationConfig;

    @BeforeClass
    public void initTest() throws Exception {

        DAOUtils.initializeDataSource(DB_NAME, DAOUtils.getFilePath("token.sql"));
        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getProperty(OAUTH_TOKEN_PERSISTENCE_POOL_SIZE)).thenReturn("0");
        when(IdentityUtil.getProperty(FRAMEWORK_PERSISTENCE_POOL_SIZE)).thenReturn("0");
        when(IdentityUtil.getProperty(OAUTH_TOKEN_PERSISTENCE_RETRY_COUNT)).thenReturn(null);

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedOAuthServerConfiguration);
        when(mockedOAuthServerConfiguration.getPersistenceProcessor()).thenReturn(new PlainTextPersistenceProcessor());
        when(mockedOAuthServerConfiguration.getHashAlgorithm()).thenReturn("SHA-256");

        OAuthComponentServiceHolder.getInstance().setRealmService(mockedRealmService);
        when(mockedRealmService.getTenantManager()).thenReturn(mockedTenantManager);
        when(mockedTenantManager.getTenantId(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME)).thenReturn
                (MultitenantConstants.SUPER_TENANT_ID);
        when(mockedTenantManager.getTenantId(SAMPLE_TENANT_DOMAIN)).thenReturn(SAMPLE_TENANT_ID);

        when(mockedApplicationManagementService.getServiceProviderByClientId(anyString(), anyString(), anyString()))
                .thenReturn(mockedServiceProvider);
        when(mockedServiceProvider.getLocalAndOutBoundAuthenticationConfig()).thenReturn
                (mockedLocalAndOutboundAuthenticationConfig);
        OAuth2ServiceComponentHolder.setApplicationMgtService(mockedApplicationManagementService);

        accessTokenDAO = new AccessTokenDAOImpl();

    }

    @BeforeMethod
    public void mockStaticMethods() throws Exception {

        mockStatic(OAuthServerConfiguration.class);
        mockStatic(IdentityUtil.class);
        mockStatic(IdentityDatabaseUtil.class);

        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedOAuthServerConfiguration);
        when(mockedOAuthServerConfiguration.getPersistenceProcessor()).thenReturn(new PlainTextPersistenceProcessor());
    }

    @DataProvider(name = "conAppKeyViolationRecoveryDataProvider")
    public Object[][] conAppKeyViolationRecoveryData() {

        // The data provider will have the following information,
        // { tenantDomain, tenantId, domainName, user, grantType, isJWTToken, isExistingToken, isExpiredToken }
        return new Object[][]{
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME, MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME, OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE, false, true, false
                },
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME, MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME, OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE, false, true, true
                },
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME, MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME, OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE, false, false, false
                },
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME, MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME, OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE, true, true, false
                },
                {
                        SAMPLE_TENANT_DOMAIN, SAMPLE_TENANT_ID, UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER, OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        false, true, false
                }
        };
    }

    @Test(dataProvider = "conAppKeyViolationRecoveryDataProvider")
    public void testConAppKeyViolationRecovery(String tenantDomain, int tenantId, String userStoreDomain, String
            applicationType, String grantType, Boolean isJWTToken, Boolean isExistingToken, Boolean isExpiredToken)
            throws Exception {

        Connection connection1 = DAOUtils.getConnection(DB_NAME);
        Connection connection2 = DAOUtils.getConnection(DB_NAME);

        OauthTokenIssuer oauthTokenIssuer;
        if (isJWTToken) {
            when(mockedOAuthServerConfiguration.getSignatureAlgorithm()).thenReturn("NONE");
            oauthTokenIssuer = spy(new JWTTokenIssuer());
        } else {
            oauthTokenIssuer = new OauthTokenIssuerImpl();
        }
        setMockOauthAppDO(UUID.randomUUID().toString());

        String consumerKey = UUID.randomUUID().toString();
        AccessTokenDAOImpl accessTokenDAO = new AccessTokenDAOImpl();

        when(mockedOAuthServerConfiguration.getIdentityOauthTokenIssuer()).thenReturn(oauthTokenIssuer);
        when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection1);

        AccessTokenDO accessTokenDO = null;
        if (isExistingToken) {
            long timeToExpire = 0L;
            if (!isExpiredToken) {
                timeToExpire = -1L;
            }
            accessTokenDO = getAccessTokenDO(consumerKey, tenantDomain, tenantId, userStoreDomain, applicationType,
                    grantType, OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE, null, isJWTToken,
                    timeToExpire);
            persistAccessToken(consumerKey, tenantId, userStoreDomain, true, accessTokenDO);
        }

        AccessTokenDO newAccessTokenDO = getAccessTokenDO(consumerKey, tenantDomain, tenantId, userStoreDomain,
                applicationType, grantType, OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE, null, isJWTToken,
                DEFAULT_TOKEN_VALIDITY_TIME);
        accessTokenDAO.recoverFromConAppKeyConstraintViolation(newAccessTokenDO.getAccessToken(), consumerKey,
                newAccessTokenDO, connection2, userStoreDomain, 0);

        if (isExistingToken && isJWTToken) {
            assertEquals(getAccessTokenStatusByTokenId(accessTokenDO.getTokenId()), "EXPIRED");
            assertEquals(getAccessTokenStatusByTokenId(newAccessTokenDO.getTokenId()), "ACTIVE");
        } else if (isExistingToken && isExpiredToken) {
            assertEquals(getAccessTokenStatusByTokenId(accessTokenDO.getTokenId()), "EXPIRED");
            assertEquals(getAccessTokenStatusByTokenId(newAccessTokenDO.getTokenId()), "ACTIVE");
        } else if (isExistingToken && !isExpiredToken && !isJWTToken) {
            assertEquals(getAccessTokenStatusByTokenId(accessTokenDO.getTokenId()), "ACTIVE");
            assertEquals(accessTokenDO.getAccessToken(), newAccessTokenDO.getAccessToken());
        }
    }

    private void setMockOauthAppDO(String consumerKey) {

        OAuthAppDO oAuthAppDO = new OAuthAppDO();
        if (consumerKey.isEmpty()) {
            consumerKey = "testConsumerKey";
        }
        oAuthAppDO.setOauthConsumerKey(consumerKey);
        oAuthAppDO.setTokenType("Default");
        mockStatic(AppInfoCache.class);
        AppInfoCache appInfoCache = Mockito.mock(AppInfoCache.class);
        when(AppInfoCache.getInstance()).thenReturn(appInfoCache);
        when(appInfoCache.getValueFromCache(any(String.class))).
                thenReturn(oAuthAppDO);
    }

    private void persistAccessToken(String consumerKey, int tenantId, String userStoreDomain, boolean
            createApplication, AccessTokenDO accessTokenDO) throws Exception {

        if (createApplication) {
            createApplication(consumerKey, UUID.randomUUID().toString(), tenantId);
        }
        accessTokenDAO.insertAccessToken(accessTokenDO.getAccessToken(), consumerKey, accessTokenDO, userStoreDomain);
    }

    private AuthenticatedUser getAuthenticatedUser(String tenantDomain, String userStoreDomain) {

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName("sampleUser");
        authenticatedUser.setTenantDomain(tenantDomain);
        authenticatedUser.setUserStoreDomain(userStoreDomain);
        return authenticatedUser;
    }

    private AccessTokenDO getAccessTokenDO(String consumerKey, String tenantDomain, int tenantId, String
            userStoreDomain, String applicationType, String grantType, String tokenState, String[] scope, Boolean
                                                   isJWTToken, long validityPeriod) {

        AuthenticatedUser authenticatedUser = getAuthenticatedUser(tenantDomain, userStoreDomain);
        return getAccessTokenDO(consumerKey, authenticatedUser, applicationType, tenantId, grantType, tokenState,
                scope, isJWTToken, validityPeriod);
    }

    private AccessTokenDO getAccessTokenDO(String consumerKey, AuthenticatedUser authenticatedUser, String
            applicationType, int tenantId, String grantType, String tokenState, String[] scope, Boolean isJWTToken,
                                           long validityPeriod) {

        AccessTokenDO accessTokenDO = new AccessTokenDO(consumerKey, authenticatedUser, new String[]{VALID_SCOPE_1},
                new Timestamp(System.currentTimeMillis()), new Timestamp(System.currentTimeMillis()), validityPeriod,
                DEFAULT_TOKEN_VALIDITY_TIME, applicationType);
        if (isJWTToken) {
            accessTokenDO.setAccessToken(JWT_TOKEN);
        } else {
            accessTokenDO.setAccessToken(UUID.randomUUID().toString());
        }
        accessTokenDO.setRefreshToken(UUID.randomUUID().toString());
        accessTokenDO.setTenantID(tenantId);
        accessTokenDO.setTokenId(UUID.randomUUID().toString());
        accessTokenDO.setGrantType(grantType);
        accessTokenDO.setTokenState(tokenState);
        if (scope != null) {
            accessTokenDO.setScope(scope);
        }
        return accessTokenDO;
    }

    private void createApplication(String consumerKey, String consumerSecret, int tenantId) throws Exception {

        try (Connection connection = DAOUtils.getConnection(DB_NAME);
             PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.OAuthAppDAOSQLQueries.ADD_OAUTH_APP)) {
            prepStmt.setString(1, consumerKey);
            prepStmt.setString(2, consumerSecret);
            prepStmt.setString(3, "testUser");
            prepStmt.setInt(4, tenantId);
            prepStmt.setString(5, UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME);
            prepStmt.setString(6, "oauth2-app");
            prepStmt.setString(7, "OAuth-2.0");
            prepStmt.setString(8, CALLBACK_URL);
            prepStmt.setString(9, "refresh_token urn:ietf:params:oauth:grant-type:saml2-bearer implicit password " +
                    "client_credentials iwa:ntlm authorization_code urn:ietf:params:oauth:grant-type:jwt-bearer");
            prepStmt.setLong(10, 3600L);
            prepStmt.setLong(11, 3600L);
            prepStmt.setLong(12, 84600L);
            prepStmt.execute();
            connection.commit();
        }
    }

    private String getAccessTokenStatusByTokenId(String accessTokenId) throws Exception {

        try (Connection connection = DAOUtils.getConnection(DB_NAME);
             PreparedStatement prepStmt = connection.prepareStatement(DAOConstants.TOKEN_STATUS_BY_TOKE)) {
            prepStmt.setString(1, accessTokenId);
            try (ResultSet resultSet = prepStmt.executeQuery()) {
                if (resultSet.next()) {
                    return resultSet.getString(1);
                }
            }
        }
        return null;
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }
}
