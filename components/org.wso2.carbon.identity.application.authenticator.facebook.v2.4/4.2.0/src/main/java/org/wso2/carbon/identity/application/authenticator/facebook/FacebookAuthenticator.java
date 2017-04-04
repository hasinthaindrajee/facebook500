package org.wso2.carbon.identity.application.authenticator.facebook;

import org.apache.amber.oauth2.client.request.OAuthClientRequest;
import org.apache.amber.oauth2.client.response.OAuthAuthzResponse;
import org.apache.amber.oauth2.common.exception.OAuthProblemException;
import org.apache.amber.oauth2.common.exception.OAuthSystemException;
import org.apache.amber.oauth2.common.utils.JSONUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.ApplicationAuthenticatorException;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.ui.CarbonUIUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.List;
import java.util.ArrayList;

/**
 * Username Password based Authenticator
 */
public class FacebookAuthenticator extends AbstractApplicationAuthenticator
        implements FederatedApplicationAuthenticator {

    private static final Log log = LogFactory.getLog(org.wso2.carbon.identity.application.authenticator.facebook
                                                                .FacebookAuthenticator.class);

    @Override
    public boolean canHandle(HttpServletRequest request) {

        log.trace("Inside FacebookAuthenticator.canHandle()");

        // Check commonauth got an OIDC response
        if (request.getParameter(FacebookAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE) != null &&
            request.getParameter(FacebookAuthenticatorConstants.OAUTH2_PARAM_STATE) != null &&
            FacebookAuthenticatorConstants.FACEBOOK_LOGIN_TYPE.equals(getLoginType(request))) {
            return true;
        }

        return false;
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        try {
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            String clientId = authenticatorProperties.get(FacebookAuthenticatorConstants.CLIENT_ID);
            String authorizationEP = FacebookAuthenticatorConstants.FB_AUTHZ_URL;
            String scope = authenticatorProperties.get(FacebookAuthenticatorConstants.SCOPE);
            if (StringUtils.isEmpty(scope)) {
                scope = FacebookAuthenticatorConstants.EMAIL;
            }

            String callbackurl = CarbonUIUtil.getAdminConsoleURL(request);
            callbackurl = callbackurl.replace("commonauth/carbon/", "commonauth");

            String state = context.getContextIdentifier() + "," + FacebookAuthenticatorConstants.FACEBOOK_LOGIN_TYPE;

            OAuthClientRequest authzRequest =
                    OAuthClientRequest.authorizationLocation(authorizationEP)
                            .setClientId(clientId)
                            .setRedirectURI(callbackurl)
                            .setResponseType(FacebookAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE)
                            .setScope(scope).setState(state)
                            .buildQueryMessage();
            response.sendRedirect(authzRequest.getLocationUri());
        } catch (IOException e) {
            log.error("Exception while sending to the login page.", e);
            throw new AuthenticationFailedException(e.getMessage(), e);
        } catch (OAuthSystemException e) {
            log.error("Exception while building authorization code request.", e);
            throw new AuthenticationFailedException(e.getMessage(), e);
        }
        return;
    }

    private String getClientID(Map<String, String> authenticatorProperties, String clientId) {
        return authenticatorProperties.get(clientId);
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request,
                                                 HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {

        log.trace("Inside FacebookAuthenticator.authenticate()");

        try {
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            String clientId = authenticatorProperties.get(FacebookAuthenticatorConstants.CLIENT_ID);
            String clientSecret =
                    authenticatorProperties.get(FacebookAuthenticatorConstants.CLIENT_SECRET);
            String userInfoFields = authenticatorProperties.get(FacebookAuthenticatorConstants.USER_INFO_FIELDS);

            String tokenEndPoint = FacebookAuthenticatorConstants.FB_TOKEN_URL;
            String fbauthUserInfoUrl = FacebookAuthenticatorConstants.FB_USER_INFO_URL;

            String callbackurl = CarbonUIUtil.getAdminConsoleURL(request);
            callbackurl = callbackurl.replace("commonauth/carbon/", "commonauth");

            String code = getAuthorizationCode(request);
            String token = getToken(tokenEndPoint, clientId, clientSecret, callbackurl, code);

            if (!StringUtils.isBlank(userInfoFields)) {
                if (context.getExternalIdP().getIdentityProvider().getClaimConfig() != null && !StringUtils.isBlank
                        (context.getExternalIdP().getIdentityProvider().getClaimConfig().getUserClaimURI())) {
                    String userClaimUri = context.getExternalIdP().getIdentityProvider().getClaimConfig()
                                                 .getUserClaimURI();
                    if (!Arrays.asList(userInfoFields.split(",")).contains(userClaimUri)) {
                        userInfoFields += ("," + userClaimUri);
                    }
                } else {
                    if (!Arrays.asList(userInfoFields.split(",")).contains(FacebookAuthenticatorConstants
                                                                                   .DEFAULT_USER_IDENTIFIER)) {
                        userInfoFields += ("," + FacebookAuthenticatorConstants.DEFAULT_USER_IDENTIFIER);
                    }
                }
            }

            Map<String, Object> userInfoJson = getUserInfoJson(fbauthUserInfoUrl, userInfoFields, token);
            buildClaims(context, userInfoJson);
        } catch (ApplicationAuthenticatorException e) {
            log.error("Failed to process Facebook Connect response.", e);
            throw new AuthenticationFailedException(e.getMessage(), e);
        }
    }

    private String getAuthorizationCode(HttpServletRequest request) throws ApplicationAuthenticatorException {
        OAuthAuthzResponse authzResponse;
        try {
            authzResponse = OAuthAuthzResponse.oauthCodeAuthzResponse(request);
            return authzResponse.getCode();
        } catch (OAuthProblemException e) {
            throw new ApplicationAuthenticatorException("Exception while reading authorization code.", e);
        }
    }

    private String getToken(String tokenEndPoint, String clientId, String clientSecret,
                            String callbackurl, String code) throws ApplicationAuthenticatorException {
        OAuthClientRequest tokenRequest = null;

        String token;

        try {
            tokenRequest =
                    buidTokenRequest(tokenEndPoint, clientId, clientSecret, callbackurl,
                                     code);

            String jsonToken = sendRequest(tokenRequest.getLocationUri());
            JSONObject jsonObject = new JSONObject(jsonToken);

            token = jsonObject.getString("access_token");
            if (token == null) {
                if (log.isDebugEnabled()) {
                    log.debug("Received token: " + jsonToken + " for code: " + code);

                }
                throw new ApplicationAuthenticatorException("Received access token is invalid.");
            }
        } catch (MalformedURLException e) {
            if (log.isDebugEnabled()) {
                log.debug("URL : " + tokenRequest.getLocationUri());
            }
            throw new ApplicationAuthenticatorException(
                    "MalformedURLException while sending access token request.",
                    e);

        } catch (IOException e) {
            throw new ApplicationAuthenticatorException("IOException while sending access token request.", e);
        } catch (JSONException e) {
            throw new ApplicationAuthenticatorException("JSONException while parsing response.", e);
        }
        return token;
    }

    private OAuthClientRequest buidTokenRequest(
            String tokenEndPoint, String clientId, String clientSecret, String callbackurl, String code)
            throws ApplicationAuthenticatorException {

        OAuthClientRequest tokenRequest = null;
        try {
            tokenRequest =
                    OAuthClientRequest.tokenLocation(tokenEndPoint).setClientId(clientId)
                            .setClientSecret(clientSecret)
                            .setRedirectURI(callbackurl).setCode(code)
                            .buildQueryMessage();
        } catch (OAuthSystemException e) {
            throw new ApplicationAuthenticatorException("Exception while building access token request.", e);
        }
        return tokenRequest;
    }

    private String getUserInfoString(String fbauthUserInfoUrl, String userInfoFields, String token)
            throws ApplicationAuthenticatorException {

        String userInfoString;
        try {
            if (StringUtils.isBlank(userInfoFields)) {
                userInfoString = sendRequest(String.format("%s?access_token=%s", fbauthUserInfoUrl, token));
            } else {
                userInfoString = sendRequest(String.format("%s?fields=%s&access_token=%s", fbauthUserInfoUrl, userInfoFields, token));
            }
        } catch (MalformedURLException e) {
            if (log.isDebugEnabled()) {
                log.debug("URL : " + fbauthUserInfoUrl + token, e);
            }
            throw new ApplicationAuthenticatorException(
                    "MalformedURLException while sending user information request.",
                    e);
        } catch (IOException e) {
            throw new ApplicationAuthenticatorException(
                    "IOException while sending sending user information request.",
                    e);
        }
        return userInfoString;
    }

    private String sendRequest(String fbauthUserInfoUrl, String token) throws IOException {
        URLConnection urlConnection = new URL(fbauthUserInfoUrl).openConnection();
        String bearer = "Bearer " + token;
        urlConnection.setRequestProperty("Authorization", bearer);
        BufferedReader in =
                new BufferedReader(
                        new InputStreamReader(urlConnection.getInputStream()));
        StringBuilder b = new StringBuilder();
        String inputLine = in.readLine();
        while (inputLine != null) {
            b.append(inputLine).append("\n");
            inputLine = in.readLine();
        }
        in.close();
        return b.toString();
    }

    private void setSubject(AuthenticationContext context, Map<String, Object> jsonObject)
            throws ApplicationAuthenticatorException {
        String authenticatedUserId = (String) jsonObject.get(FacebookAuthenticatorConstants.DEFAULT_USER_IDENTIFIER);

        if (StringUtils.isEmpty(authenticatedUserId)) {
            throw new ApplicationAuthenticatorException("Authenticated user identifier is empty");
        }
        context.setSubject(authenticatedUserId);
    }

    private Map<String, Object> getUserInfoJson(String fbauthUserInfoUrl, String userInfoFields, String token)
            throws ApplicationAuthenticatorException {
        Map<String, Object> jsonObject;
        String userInfoString = getUserInfoString(fbauthUserInfoUrl, userInfoFields, token);
        try {
            jsonObject = JSONUtils.parseJSON(userInfoString);
        } catch (JSONException e) {
            if (log.isDebugEnabled()) {
                log.debug("UserInfoString : " + userInfoString, e);
            }
            throw new ApplicationAuthenticatorException("Exception while parsing User Information.", e);
        }
        return jsonObject;
    }

    public void buildClaims(AuthenticationContext context, Map<String, Object> jsonObject)
            throws ApplicationAuthenticatorException {
        if (jsonObject != null) {
            Map<ClaimMapping, String> claims = new HashMap<ClaimMapping, String>();

            for (Map.Entry<String, Object> entry : jsonObject.entrySet()) {
                claims.put(ClaimMapping.build(entry.getKey(), entry.getKey(), null,
                                              false), entry.getValue().toString());
                if (log.isDebugEnabled()) {
                    log.debug("Adding claim mapping : " + entry.getKey() + " <> " + entry.getKey() + " : "
                                 + entry.getValue());
                }

            }
            context.setSubjectAttributes(claims);
            context.getExternalIdP().getUserIdClaimUri();

            String subjectFromClaims = FrameworkUtils.getFederatedSubjectFromClaims(
                    context.getExternalIdP().getIdentityProvider(), claims);
            if (subjectFromClaims != null && !subjectFromClaims.isEmpty()) {
                context.setSubject(subjectFromClaims);
            } else {
                setSubject(context, jsonObject);
            }

        } else {
            if (log.isDebugEnabled()) {
                log.debug("Decoded json object is null");
            }
            throw new ApplicationAuthenticatorException("Decoded json object is null");
        }
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {
        log.trace("Inside FacebookAuthenticator.getContextIdentifier()");
        String state = request.getParameter(FacebookAuthenticatorConstants.OAUTH2_PARAM_STATE);
        if (state != null) {
            return state.split(",")[0];
        } else {
            return null;
        }
    }

    private String sendRequest(String url) throws IOException {
        URLConnection urlConnection = new URL(url).openConnection();
        BufferedReader in =
                new BufferedReader(
                        new InputStreamReader(urlConnection.getInputStream()));
        StringBuilder b = new StringBuilder();
        String inputLine = in.readLine();
        while (inputLine != null) {
            b.append(inputLine).append("\n");
            inputLine = in.readLine();
        }
        in.close();
        return b.toString();
    }

    private String getLoginType(HttpServletRequest request) {
        String state = request.getParameter(FacebookAuthenticatorConstants.OAUTH2_PARAM_STATE);
        if (state != null) {
            return state.split(",")[1];
        } else {
            return null;
        }
    }

    @Override
    public String getFriendlyName() {
        return FacebookAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public String getName() {
        return FacebookAuthenticatorConstants.AUTHENTICATOR_NAME;
    }

    @Override
    public List<Property> getConfigurationProperties() {
        List configProperties = new ArrayList();

        Property clientId = new Property();
        clientId.setName("ClientId");
        clientId.setDisplayName("Client Id");
        clientId.setRequired(true);
        clientId.setDescription("Enter Facebook client identifier value");
        configProperties.add(clientId);

        Property clientSecret = new Property();
        clientSecret.setName("ClientSecret");
        clientSecret.setDisplayName("Client Secret");
        clientSecret.setRequired(true);
        clientSecret.setConfidential(true);
        clientSecret.setDescription("Enter Facebook client secret value");
        configProperties.add(clientSecret);

        Property scope = new Property();
        scope.setName("Scope");
        scope.setDisplayName("Scope");
        scope.setRequired(false);
        scope.setDefaultValue("email");
        scope.setDescription("Enter a comma separated list of permissions to request from the user");
        configProperties.add(scope);

        Property userInfoFields = new Property();
        userInfoFields.setName(FacebookAuthenticatorConstants.USER_INFO_FIELDS);
        userInfoFields.setDisplayName("User Information Fields");
        userInfoFields.setRequired(false);
        userInfoFields.setDefaultValue(FacebookAuthenticatorConstants.DEFAULT_USER_IDENTIFIER);
        userInfoFields.setDescription("Enter comma-separated user information fields you want to retrieve");
        configProperties.add(userInfoFields);

        return configProperties;
    }
}