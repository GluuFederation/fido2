/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.fido2.service.app;

import java.lang.annotation.Annotation;
import java.util.List;
import java.util.Properties;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.context.BeforeDestroyed;
import javax.enterprise.context.Initialized;
import javax.enterprise.event.Event;
import javax.enterprise.event.Observes;
import javax.enterprise.inject.Instance;
import javax.enterprise.inject.Produces;
import javax.enterprise.inject.spi.BeanManager;
import javax.inject.Inject;
import javax.inject.Named;
import javax.servlet.ServletContext;

import org.gluu.exception.ConfigurationException;
import org.gluu.fido2.service.shared.LoggerService;
import org.gluu.fido2.service.shared.MetricService;
import org.gluu.model.custom.script.CustomScriptType;
import org.gluu.orm.util.properties.FileConfiguration;
import org.gluu.oxauth.service.common.ApplicationFactory;
import org.gluu.oxauth.service.common.EncryptionService;
import org.gluu.persist.PersistenceEntryManager;
import org.gluu.persist.model.PersistenceConfiguration;
import org.gluu.service.PythonService;
import org.gluu.service.cdi.event.ApplicationInitialized;
import org.gluu.service.cdi.event.ApplicationInitializedEvent;
import org.gluu.service.cdi.event.LdapConfigurationReload;
import org.gluu.service.cdi.util.CdiUtil;
import org.gluu.service.custom.script.CustomScriptManager;
import org.gluu.service.metric.inject.ReportMetric;
import org.gluu.service.timer.QuartzSchedulerManager;
import org.gluu.util.StringHelper;
import org.gluu.util.security.SecurityProviderUtility;
import org.gluu.util.security.StringEncrypter;
import org.gluu.util.security.StringEncrypter.EncryptionException;
import org.slf4j.Logger;

import com.google.common.collect.Lists;

/**
 * 
 * FIDO2 server initializer
 * @author Yuriy MOvchan
 * @version May 12, 2020
 */
@ApplicationScoped
@Named
public class AppInitializer {

	@Inject
	private Logger log;

	@Inject
	private BeanManager beanManager;

	@Inject
	private Event<ApplicationInitializedEvent> eventApplicationInitialized;

	@Inject
	@Named(ApplicationFactory.PERSISTENCE_ENTRY_MANAGER_NAME)
	private Instance<PersistenceEntryManager> persistenceEntryManagerInstance;

	@Inject
	@Named(ApplicationFactory.PERSISTENCE_ENTRY_MANAGER_NAME)
	@ReportMetric
	private Instance<PersistenceEntryManager> persistenceMetricEntryManagerInstance;

	@Inject
	private ApplicationFactory applicationFactory;

	@Inject
	private Instance<EncryptionService> encryptionServiceInstance;

	@Inject
	private PythonService pythonService;

	@Inject
	private MetricService metricService;

	@Inject
	private CustomScriptManager customScriptManager;

	@Inject
	private ConfigurationFactory configurationFactory;

	@Inject
	private CleanerTimer cleanerTimer;

	@Inject
	private QuartzSchedulerManager quartzSchedulerManager;

	@Inject
	private LoggerService loggerService;

	@Inject
	private MDS3UpdateTimer mds3UpdateTimer;

	@PostConstruct
	public void createApplicationComponents() {
		try {
			SecurityProviderUtility.installBCProvider();
		} catch (ClassCastException ex) {
			log.error("Failed to install BC provider properly");
		}
	}

	public void applicationInitialized(@Observes @Initialized(ApplicationScoped.class) Object init) {
		log.debug("Initializing application services");

		configurationFactory.create();

		PersistenceEntryManager localPersistenceEntryManager = persistenceEntryManagerInstance.get();
		log.trace("Attempting to use {}: {}", ApplicationFactory.PERSISTENCE_ENTRY_MANAGER_NAME,
				localPersistenceEntryManager.getOperationService());

		// Initialize python interpreter
		pythonService
				.initPythonInterpreter(configurationFactory.getBaseConfiguration().getString("pythonModulesDir", null));

		// Initialize script manager
		List<CustomScriptType> supportedCustomScriptTypes = Lists.newArrayList(CustomScriptType.FIDO2_EXTENSION);

		// Start timer
		initSchedulerService();

		// Schedule timer tasks
		metricService.initTimer();
		configurationFactory.initTimer();
		loggerService.initTimer(true);
		cleanerTimer.initTimer();
		mds3UpdateTimer.initTimer();
		customScriptManager.initTimer(supportedCustomScriptTypes);

		// Notify plugins about finish application initialization
		eventApplicationInitialized.select(ApplicationInitialized.Literal.APPLICATION)
				.fire(new ApplicationInitializedEvent());
	}

	protected void initSchedulerService() {
		quartzSchedulerManager.start();

		String disableScheduler = System.getProperties().getProperty("gluu.disable.scheduler");
		if ((disableScheduler != null) && Boolean.valueOf(disableScheduler)) {
			this.log.warn("Suspending Quartz Scheduler Service...");
			quartzSchedulerManager.standby();
			return;
		}
	}

	@Produces
	@ApplicationScoped
	public StringEncrypter getStringEncrypter() {
		String encodeSalt = configurationFactory.getCryptoConfigurationSalt();

		if (StringHelper.isEmpty(encodeSalt)) {
			throw new ConfigurationException("Encode salt isn't defined");
		}

		try {
			StringEncrypter stringEncrypter = StringEncrypter.instance(encodeSalt);

			return stringEncrypter;
		} catch (EncryptionException ex) {
			throw new ConfigurationException("Failed to create StringEncrypter instance");
		}
	}

	protected Properties preparePersistanceProperties() {
		PersistenceConfiguration persistenceConfiguration = this.configurationFactory.getPersistenceConfiguration();
		FileConfiguration persistenceConfig = persistenceConfiguration.getConfiguration();
		Properties connectionProperties = (Properties) persistenceConfig.getProperties();

		EncryptionService securityService = encryptionServiceInstance.get();
		Properties decryptedConnectionProperties = securityService.decryptAllProperties(connectionProperties);
		return decryptedConnectionProperties;
	}

	protected Properties prepareCustomPersistanceProperties(String configId) {
		Properties connectionProperties = preparePersistanceProperties();
		if (StringHelper.isNotEmpty(configId)) {
			// Replace properties names 'configId.xyz' to 'configId.xyz' in order to
			// override default values
			connectionProperties = (Properties) connectionProperties.clone();

			String baseGroup = configId + ".";
			for (Object key : connectionProperties.keySet()) {
				String propertyName = (String) key;
				if (propertyName.startsWith(baseGroup)) {
					propertyName = propertyName.substring(baseGroup.length());

					Object value = connectionProperties.get(key);
					connectionProperties.put(propertyName, value);
				}
			}
		}

		return connectionProperties;
	}

	@Produces
	@ApplicationScoped
	@Named(ApplicationFactory.PERSISTENCE_ENTRY_MANAGER_NAME)
	public PersistenceEntryManager createPersistenceEntryManager() {
		Properties connectionProperties = preparePersistanceProperties();

		PersistenceEntryManager persistenceEntryManager = applicationFactory.getPersistenceEntryManagerFactory()
				.createEntryManager(connectionProperties);
		log.info("Created {}: {} with operation service: {}",
				new Object[] { ApplicationFactory.PERSISTENCE_ENTRY_MANAGER_NAME, persistenceEntryManager,
						persistenceEntryManager.getOperationService() });

		return persistenceEntryManager;
	}

	@Produces
	@ApplicationScoped
	@Named(ApplicationFactory.PERSISTENCE_METRIC_ENTRY_MANAGER_NAME)
	@ReportMetric
	public PersistenceEntryManager createMetricPersistenceEntryManager() {
		Properties connectionProperties = prepareCustomPersistanceProperties(
				ApplicationFactory.PERSISTENCE_METRIC_CONFIG_GROUP_NAME);

		PersistenceEntryManager persistenceEntryManager = applicationFactory.getPersistenceEntryManagerFactory()
				.createEntryManager(connectionProperties);
		log.info("Created {}: {} with operation service: {}",
				new Object[] { ApplicationFactory.PERSISTENCE_METRIC_ENTRY_MANAGER_NAME, persistenceEntryManager,
						persistenceEntryManager.getOperationService() });

		return persistenceEntryManager;
	}

	public void recreatePersistenceEntryManager(@Observes @LdapConfigurationReload String event) {
		recreatePersistanceEntryManagerImpl(persistenceEntryManagerInstance,
				ApplicationFactory.PERSISTENCE_ENTRY_MANAGER_NAME);

		recreatePersistanceEntryManagerImpl(persistenceEntryManagerInstance,
				ApplicationFactory.PERSISTENCE_METRIC_ENTRY_MANAGER_NAME, ReportMetric.Literal.INSTANCE);
	}

	protected void recreatePersistanceEntryManagerImpl(Instance<PersistenceEntryManager> instance,
			String persistenceEntryManagerName, Annotation... qualifiers) {
		// Get existing application scoped instance
		PersistenceEntryManager oldPersistenceEntryManager = CdiUtil.getContextBean(beanManager,
				PersistenceEntryManager.class, persistenceEntryManagerName);

		// Close existing connections
		closePersistenceEntryManager(oldPersistenceEntryManager, persistenceEntryManagerName);

		// Force to create new bean
		PersistenceEntryManager persistenceEntryManager = instance.get();
		instance.destroy(persistenceEntryManager);
		log.info("Recreated instance {}: {} with operation service: {}", persistenceEntryManagerName,
				persistenceEntryManager, persistenceEntryManager.getOperationService());
	}

	private void closePersistenceEntryManager(PersistenceEntryManager oldPersistenceEntryManager,
			String persistenceEntryManagerName) {
		// Close existing connections
		if ((oldPersistenceEntryManager != null) && (oldPersistenceEntryManager.getOperationService() != null)) {
			log.debug("Attempting to destroy {}:{} with operation service: {}", persistenceEntryManagerName,
					oldPersistenceEntryManager, oldPersistenceEntryManager.getOperationService());
			oldPersistenceEntryManager.destroy();
			log.debug("Destroyed {}:{} with operation service: {}", persistenceEntryManagerName,
					oldPersistenceEntryManager, oldPersistenceEntryManager.getOperationService());
		}
	}

	public void destroy(@Observes @BeforeDestroyed(ApplicationScoped.class) ServletContext init) {
		log.info("Stopping services and closing DB connections at server shutdown...");
		log.debug("Checking who intiated destroy", new Throwable());

		metricService.close();

		PersistenceEntryManager persistenceEntryManager = persistenceEntryManagerInstance.get();
		closePersistenceEntryManager(persistenceEntryManager, ApplicationFactory.PERSISTENCE_ENTRY_MANAGER_NAME);
	}

}
