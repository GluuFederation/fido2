package org.gluu.fido2.service.app;

import java.util.HashSet;
import java.util.Set;

import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Application;

import org.gluu.fido2.ws.rs.controller.HealthCheckController;

/**
 * Integration with Resteasy
 * 
 * @author Yuriy Movchan
 * @version 0.1, 11/13/2020
 */
@ApplicationPath("/sys")
public class SystemResteasyInitializer extends Application {	

	@Override
    public Set<Class<?>> getClasses() {
        HashSet<Class<?>> classes = new HashSet<Class<?>>();
        classes.add(HealthCheckController.class);

        return classes;
    }

}
