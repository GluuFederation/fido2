package org.gluu.fido2.service.app;

import java.util.HashSet;
import java.util.Set;

import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Application;

import org.gluu.fido2.ws.rs.controller.AssertionController;
import org.gluu.fido2.ws.rs.controller.AttestationController;
import org.gluu.fido2.ws.rs.controller.ConfigurationController;

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