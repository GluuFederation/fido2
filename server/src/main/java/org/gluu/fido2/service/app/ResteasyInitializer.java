package org.gluu.fido2.service.app;

import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Application;

/**
 * Integration with Resteasy
 * 
 * @author Yuriy Movchan
 * @version 0.1, 03/21/2017
 */
@ApplicationPath("/restv1")
public class ResteasyInitializer extends Application {	

	@Override
    public Set<Class<?>> getClasses() {
        HashSet<Class<?>> classes = new HashSet<Class<?>>();
        classes.add(ConfigurationController.class);
        classes.add(AssertionController.class);
        classes.add(AttestationController.class);

        return classes;
    }

}