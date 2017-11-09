/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *   WSO2 Inc. licenses this file to you under the Apache License,
 *   Version 2.0 (the "License"); you may not use this file except
 *   in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.wso2.carbon.identity.oauth.endpoint.expmapper;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.as.response.OAuthASResponse;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.OAuthResponse;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.endpoint.exception.AccessDeniedException;
import org.wso2.carbon.identity.oauth.endpoint.exception.BadRequestException;
import org.wso2.carbon.identity.oauth.endpoint.exception.InvalidApplicationClientException;
import org.wso2.carbon.identity.oauth.endpoint.exception.InvalidRequestException;
import org.wso2.carbon.identity.oauth.endpoint.exception.InvalidRequestParentException;
import org.wso2.carbon.identity.oauth.endpoint.exception.TokenEndpointAccessDeniedException;
import org.wso2.carbon.identity.oauth.endpoint.exception.TokenEndpointBadRequestException;
import org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil;


import java.net.URI;
import java.net.URISyntaxException;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;

public class InvalidRequestExceptionMapper implements ExceptionMapper<InvalidRequestParentException> {

    private final Log log = LogFactory.getLog(InvalidRequestExceptionMapper.class);

    @Override
    public Response toResponse(InvalidRequestParentException exception) {

        if (exception instanceof InvalidRequestException) {
            try {
                return buildErrorResponse(exception, HttpServletResponse.SC_FOUND, OAuth2ErrorCodes.INVALID_REQUEST);
            } catch (URISyntaxException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Error while getting endpoint error page URL", e);
                }
                return handleInternalServerError();
            }
        } else if (exception instanceof AccessDeniedException) {
            try {
                return buildErrorResponse(exception, HttpServletResponse.SC_FOUND, OAuth2ErrorCodes.ACCESS_DENIED);
            } catch (URISyntaxException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Error while getting endpoint error page URL", e);
                }
                return handleInternalServerError();
            }
        } else if (exception instanceof InvalidApplicationClientException) {
            try {
                return buildErrorResponse(HttpServletResponse.SC_UNAUTHORIZED, exception, OAuth2ErrorCodes.INVALID_CLIENT);
            } catch (OAuthSystemException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Error while getting endpoint error page URL", e);
                }
                return handleInternalServerError();
            }
        }  else if (exception instanceof BadRequestException) {
            try {
                return buildErrorResponse(exception, HttpServletResponse.SC_BAD_REQUEST, OAuth2ErrorCodes.INVALID_REQUEST);
            } catch (URISyntaxException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Error while getting endpoint error page URL", e);
                }
                return handleInternalServerError();
            }
        } else if (exception instanceof TokenEndpointBadRequestException) {
            try {
                return buildErrorResponse(HttpServletResponse.SC_BAD_REQUEST, exception, OAuth2ErrorCodes.INVALID_REQUEST);
            } catch (OAuthSystemException e) {
                if (log.isDebugEnabled()) {
                    log.debug("OAuth System error while token invoking token endpoint", e);
                }
                return handleInternalServerError();
            }

        } else if (exception instanceof TokenEndpointAccessDeniedException) {
            try {
                return buildErrorResponse(HttpServletResponse.SC_UNAUTHORIZED, exception, OAuth2ErrorCodes.INVALID_CLIENT);
            } catch (OAuthSystemException e) {
                if (log.isDebugEnabled()) {
                    log.debug("OAuth System error while token invoking token endpoint", e);
                }
                return handleInternalServerError();
            }
        } else {
            return handleInternalServerError();
        }
    }

    private Response handleInternalServerError() {
        return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
    }

    private Response buildErrorResponse(InvalidRequestParentException exception, int status, String errorCode)
            throws URISyntaxException {

        if (log.isDebugEnabled()) {
            log.debug("Response status :" + status);
        }
        return Response.status(status).location(new URI(EndpointUtil.getErrorPageURL(errorCode,
                exception.getMessage(), null))).build();
    }

    private Response buildErrorResponse(int status, InvalidRequestParentException exception, String errorCode)
            throws OAuthSystemException {

        if (exception.getMessage() != null) {
            OAuthResponse oAuthResponse = OAuthASResponse
                    .errorResponse(status)
                    .setError(errorCode)
                    .setErrorDescription(exception.getMessage())
                    .buildJSONMessage();

            if (log.isDebugEnabled()) {
                log.debug("Response status :" + oAuthResponse.getResponseStatus() + " and response:" + oAuthResponse.getBody());
            }

            if (exception instanceof TokenEndpointAccessDeniedException) {
                return Response.status(oAuthResponse.getResponseStatus())
                        .header(OAuthConstants.HTTP_RESP_HEADER_AUTHENTICATE, EndpointUtil.getRealmInfo())
                        .entity(oAuthResponse.getBody()).build();
            }
            return Response.status(oAuthResponse.getResponseStatus()).entity(oAuthResponse.getBody()).build();
        } else {
            OAuthResponse oAuthResponse = OAuthASResponse
                    .errorResponse(status)
                    .error((OAuthProblemException) exception.getCause())
                    .buildJSONMessage();

            if (log.isDebugEnabled()) {
                log.debug("Response status :" + oAuthResponse.getResponseStatus() + " and response:" + oAuthResponse.getBody());
            }
            return Response.status(oAuthResponse.getResponseStatus()).entity(oAuthResponse.getBody()).build();
        }
    }
}
