package org.wso2.carbon.identity.application.authenticator.facebook.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.application.authenticator.facebook.FacebookAuthenticator;

import java.util.Hashtable;

/**
 * @scr.component name="identity.application.authenticator.facebook-v2.4" immediate="true"
 */
public class FacebookAuthenticatorServiceComponent {

    private static Log log = LogFactory.getLog(org.wso2.carbon.identity.application.authenticator.facebook.internal
                                                       .FacebookAuthenticatorServiceComponent.class);

    protected void activate(ComponentContext ctxt) {

        FacebookAuthenticator facebookAuthenticator = new FacebookAuthenticator();
        Hashtable<String, String> props = new Hashtable<String, String>();

        ctxt.getBundleContext().registerService(ApplicationAuthenticator.class.getName()
                , facebookAuthenticator, props);

        log.info("Facebook Authenticator v2.4 bundle is activated");
    }

    protected void deactivate(ComponentContext ctxt) {
        if (log.isDebugEnabled()) {
            log.debug("Facebook Authenticator v2.4 bundle is deactivated");
        }
    }

}
