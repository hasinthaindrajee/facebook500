package org.wso2.carbon.identity.application.authenticator.facebook;

/**
 * Constants used by the FacebookAuthenticator
 */
public class FacebookAuthenticatorConstants {

    public static final String AUTHENTICATOR_NAME = "FacebookAuthenticator-v2.8";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "facebook-v2.8";

    public static final String FACEBOOK_LOGIN_TYPE = "facebook-v2.8";

    public static final String OAUTH2_GRANT_TYPE_CODE = "code";
    public static final String OAUTH2_PARAM_STATE = "state";
    public static final String EMAIL = "email";

    public static final String FB_AUTHZ_URL = "http://www.facebook.com/dialog/oauth";
    public static final String FB_TOKEN_URL = "https://graph.facebook.com/v2.4/oauth/access_token";
    public static final String FB_USER_INFO_URL = "https://graph.facebook.com/v2.4/me";
    public static final String SCOPE = "Scope";

    public static final String CLIENT_ID = "ClientId";
    public static final String CLIENT_SECRET = "ClientSecret";

    public static final String USER_INFO_FIELDS = "UserInfoFields";
    public static final String DEFAULT_USER_IDENTIFIER = "id";

    private FacebookAuthenticatorConstants() {
    }
}
