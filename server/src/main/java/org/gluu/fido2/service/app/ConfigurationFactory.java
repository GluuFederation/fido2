/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.fido2.service.app;

import java.io.File;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Event;
import javax.enterprise.event.Observes;
import javax.enterprise.inject.Instance;
import javax.enterprise.inject.Produces;
import javax.inject.Inject;

import org.apache.commons.lang.StringUtils;
import org.gluu.exception.ConfigurationException;
import org.gluu.fido2.model.conf.AppConfiguration;
import org.gluu.fido2.model.conf.Conf;
import org.gluu.fido2.model.error.ErrorResponseFactory;
import org.gluu.oxauth.model.config.BaseDnConfiguration;
import org.gluu.oxauth.model.config.StaticConfiguration;
import org.gluu.oxauth.model.configuration.Configuration;
import org.gluu.oxauth.model.crypto.AbstractCryptoProvider;
import org.gluu.persist.PersistenceEntryManager;
import org.gluu.persist.exception.BasePersistenceException;
import org.gluu.persist.model.PersistenceConfiguration;
import org.gluu.persist.service.PersistanceFactoryService;
import org.gluu.service.cdi.async.Asynchronous;
import org.gluu.service.cdi.event.BaseConfigurationReload;
import org.gluu.service.cdi.event.ConfigurationEvent;
import org.gluu.service.cdi.event.ConfigurationUpdate;
import org.gluu.service.cdi.event.LdapConfigurationReload;
import org.gluu.service.cdi.event.Scheduled;
import org.gluu.service.timer.event.TimerEvent;
import org.gluu.service.timer.schedule.TimerSchedule;
import org.gluu.util.StringHelper;
import org.gluu.util.properties.FileConfiguration;
import org.slf4j.Logger;

/**
 * @author Yuriy Movchan Date: 05/13/2020
 */
@ApplicationScoped
public class ConfigurationFactory {

	@Inject
	private Logger log;

	@Inject
	private Event<TimerEvent> timerEvent;

	@Inject
	private Event<AppConfiguration> configurationUpdateEvent;

	@Inject
	private Event<String> event;

	@Inject
	private Instance<PersistenceEntryManager> persistenceEntryManagerInstance;

    @Inject
	private PersistanceFactoryService persistanceFactoryService;

	@Inject
	private Instance<Configuration> configurationInstance;

	@Inject
	private Instance<AbstractCryptoProvider> abstractCryptoProviderInstance;

	private ErrorResponseFactory errorResponseFactory;

	public final static String PERSISTENCE_CONFIGUARION_RELOAD_EVENT_TYPE = "persistenceConfigurationReloadEvent";
	public final static String BASE_CONFIGUARION_RELOAD_EVENT_TYPE = "baseConfigurationReloadEvent";

	private final static int DEFAULT_INTERVAL = 30; // 30 seconds

	static {
		if (System.getProperty("gluu.base") != null) {
			BASE_DIR = System.getProperty("gluu.base");
		} else if ((System.getProperty("catalina.base") != null) && (System.getProperty("catalina.base.ignore") == null)) {
			BASE_DIR = System.getProperty("catalina.base");
		} else if (System.getProperty("catalina.home") != null) {
			BASE_DIR = System.getProperty("catalina.home");
		} else if (System.getProperty("jboss.home.dir") != null) {
			BASE_DIR = System.getProperty("jboss.home.dir");
		} else {
			BASE_DIR = null;
		}
	}

	private static final String BASE_DIR;
	private static final String DIR = BASE_DIR + File.separator + "conf" + File.separator;

	private static final String BASE_PROPERTIES_FILE = DIR + "gluu.properties";
	private static final String APP_PROPERTIES_FILE = DIR + "fido2.properties";

	private final String SALT_FILE_NAME = "salt";

	private String confDir, saltFilePath;

	private boolean loaded = false;

	private FileConfiguration baseConfiguration;
    
    private PersistenceConfiguration persistenceConfiguration;
	private AppConfiguration dynamicConf;
	private StaticConfiguration staticConf;
	private String cryptoConfigurationSalt;

	private AtomicBoolean isActive;

	private long baseConfigurationFileLastModifiedTime;

	private long loadedRevision = -1;
	private boolean loadedFromLdap = true;

	@PostConstruct
	public void init() {
		this.isActive = new AtomicBoolean(true);
		try {
            this.persistenceConfiguration = persistanceFactoryService.loadPersistenceConfiguration(APP_PROPERTIES_FILE);
			loadBaseConfiguration();

			this.confDir = confDir();
			log.debug("confDir: {}", confDir);

			String certsDir = this.baseConfiguration.getString("certsDir");
			if (StringHelper.isEmpty(certsDir)) {
				certsDir = confDir;
			}
			this.saltFilePath = confDir + SALT_FILE_NAME;

			loadCryptoConfigurationSalt();
		} finally {
			this.isActive.set(false);
		}
	}

	public void create() {
		if (!createFromDb()) {
			log.error("Failed to load configuration from LDAP. Please fix it!!!.");
			throw new ConfigurationException("Failed to load configuration from LDAP.");
		} else {
			log.info("Configuration loaded successfully.");
		}
	}

	public void initTimer() {
		log.debug("Initializing Configuration Timer");

		final int delay = 30;
		final int interval = DEFAULT_INTERVAL;

		timerEvent.fire(new TimerEvent(new TimerSchedule(delay, interval), new ConfigurationEvent(),
				Scheduled.Literal.INSTANCE));
	}

	@Asynchronous
	public void reloadConfigurationTimerEvent(@Observes @Scheduled ConfigurationEvent configurationEvent) {
		if (this.isActive.get()) {
			return;
		}

		if (!this.isActive.compareAndSet(false, true)) {
			return;
		}

		try {
			reloadConfiguration();
		} catch (Throwable ex) {
			log.error("Exception happened while reloading application configuration", ex);
		} finally {
			this.isActive.set(false);
		}
	}

	private void reloadConfiguration() {
		// Reload LDAP configuration if needed
	    PersistenceConfiguration newPersistenceConfiguration = persistanceFactoryService.loadPersistenceConfiguration(APP_PROPERTIES_FILE);

		if (newPersistenceConfiguration != null) {
			if (!StringHelper.equalsIgnoreCase(this.persistenceConfiguration.getFileName(), newPersistenceConfiguration.getFileName()) || (newPersistenceConfiguration.getLastModifiedTime() > this.persistenceConfiguration.getLastModifiedTime())) {
				// Reload configuration only if it was modified
				this.persistenceConfiguration = newPersistenceConfiguration;
				event.select(LdapConfigurationReload.Literal.INSTANCE).fire(PERSISTENCE_CONFIGUARION_RELOAD_EVENT_TYPE);
			}
		}

        // Reload Base configuration if needed
		File baseConfiguration = new File(BASE_PROPERTIES_FILE);
		if (baseConfiguration.exists()) {
			final long lastModified = baseConfiguration.lastModified();
			if (lastModified > baseConfigurationFileLastModifiedTime) {
				// Reload configuration only if it was modified
				loadBaseConfiguration();
				event.select(BaseConfigurationReload.Literal.INSTANCE).fire(BASE_CONFIGUARION_RELOAD_EVENT_TYPE);
			}
		}

		if (!loadedFromLdap) {
			return;
		}
		
		reloadConfFromLdap();
	}

	private boolean isRevisionIncreased() {
        final Conf conf = loadConfigurationFromLdap("oxRevision");
        if (conf == null) {
            return false;
        }

        log.trace("LDAP revision: " + conf.getRevision() + ", server revision:" + loadedRevision);
        return conf.getRevision() > this.loadedRevision;
    }

	private String confDir() {
		final String confDir = this.baseConfiguration.getString("confDir", null);
		if (StringUtils.isNotBlank(confDir)) {
			return confDir;
		}

		return DIR;
	}

	public FileConfiguration getBaseConfiguration() {
		return baseConfiguration;
	}

	@Produces
    @ApplicationScoped
    public PersistenceConfiguration getPersistenceConfiguration() {
        return persistenceConfiguration;
    }

	@Produces
	@ApplicationScoped
	public AppConfiguration getAppConfiguration() {
		return dynamicConf;
	}

	@Produces
	@ApplicationScoped
	public StaticConfiguration getStaticConfiguration() {
		return staticConf;
	}

	@Produces
	@ApplicationScoped
	public ErrorResponseFactory getFido2ErrorResponseFactory() {
		return errorResponseFactory;
	}

	public BaseDnConfiguration getBaseDn() {
		return getStaticConfiguration().getBaseDn();
	}

	public String getCryptoConfigurationSalt() {
		return cryptoConfigurationSalt;
	}

	public boolean reloadConfFromLdap() {
        if (!isRevisionIncreased()) {
            return false;
        }

        return createFromDb();
    }

	private boolean createFromDb() {
		log.info("Loading configuration from '{}' DB...", baseConfiguration.getString("persistence.type"));
		try {
			final Conf c = loadConfigurationFromLdap();
			if (c != null) {
				init(c);

				// Destroy old configuration
				if (this.loaded) {
					destroy(AppConfiguration.class);
					destroy(StaticConfiguration.class);
//					destroy(Fido2ErrorResponseFactory.class);

					destroyCryptoProviderInstance(AbstractCryptoProvider.class);
				}

				this.loaded = true;
				configurationUpdateEvent.select(ConfigurationUpdate.Literal.INSTANCE).fire(dynamicConf);

				return true;
			}
		} catch (Exception ex) {
			log.error(ex.getMessage(), ex);
		}

		throw new ConfigurationException("Unable to find configuration in DB... ");
	}

	public void destroy(Class<? extends Configuration> clazz) {
		Instance<? extends Configuration> confInstance = configurationInstance.select(clazz);
		configurationInstance.destroy(confInstance.get());
	}

	public void destroyCryptoProviderInstance(Class<? extends AbstractCryptoProvider> clazz) {
		AbstractCryptoProvider abstractCryptoProvider = abstractCryptoProviderInstance.get();
		abstractCryptoProviderInstance.destroy(abstractCryptoProvider);
	}

	private Conf loadConfigurationFromLdap(String... returnAttributes) {
		final PersistenceEntryManager persistenceEntryManager = persistenceEntryManagerInstance.get();
		final String dn = this.baseConfiguration.getString("fido2_ConfigurationEntryDN");
		try {
			final Conf conf = persistenceEntryManager.find(dn, Conf.class, returnAttributes);

			return conf;
		} catch (BasePersistenceException ex) {
			log.error(ex.getMessage());
		}

		return null;
	}

	private void init(Conf conf) {
		initConfigurationConf(conf);
		this.loadedRevision = conf.getRevision();
	}

	private void initConfigurationConf(Conf conf) {
		if (conf.getDynamicConf() != null) {
			dynamicConf = conf.getDynamicConf();
		}
		if (conf.getStaticConf() != null) {
			staticConf = conf.getStaticConf();
		}
		if (conf.getErrors() != null) {
			errorResponseFactory = new ErrorResponseFactory(conf.getErrors(), conf.getDynamicConf());
		}
	}

	private void loadBaseConfiguration() {
		this.baseConfiguration = createFileConfiguration(BASE_PROPERTIES_FILE, true);

		File baseConfiguration = new File(BASE_PROPERTIES_FILE);
		this.baseConfigurationFileLastModifiedTime = baseConfiguration.lastModified();
	}

	public void loadCryptoConfigurationSalt() {
		try {
			FileConfiguration cryptoConfiguration = createFileConfiguration(saltFilePath, true);

			this.cryptoConfigurationSalt = cryptoConfiguration.getString("encodeSalt");
		} catch (Exception ex) {
			log.error("Failed to load configuration from {}", saltFilePath, ex);
			throw new ConfigurationException("Failed to load configuration from " + saltFilePath, ex);
		}
	}

	private FileConfiguration createFileConfiguration(String fileName, boolean isMandatory) {
		try {
			FileConfiguration fileConfiguration = new FileConfiguration(fileName);

			return fileConfiguration;
		} catch (Exception ex) {
			if (isMandatory) {
				log.error("Failed to load configuration from {}", fileName, ex);
				throw new ConfigurationException("Failed to load configuration from " + fileName, ex);
			}
		}

		return null;
	}


}
