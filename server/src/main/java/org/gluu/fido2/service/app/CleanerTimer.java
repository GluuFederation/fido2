/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.fido2.service.app;

import java.util.Date;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Event;
import javax.enterprise.event.Observes;
import javax.inject.Inject;
import javax.inject.Named;

import org.gluu.fido2.model.conf.AppConfiguration;
import org.gluu.fido2.service.persist.AuthenticationPersistenceService;
import org.gluu.fido2.service.persist.RegistrationPersistenceService;
import org.gluu.oxauth.model.config.StaticConfiguration;
import org.gluu.persist.PersistenceEntryManager;
import org.gluu.persist.model.base.SimpleBranch;
import org.gluu.persist.model.fido2.Fido2AuthenticationEntry;
import org.gluu.persist.model.fido2.Fido2RegistrationEntry;
import org.gluu.search.filter.Filter;
import org.gluu.service.cdi.async.Asynchronous;
import org.gluu.service.cdi.event.CleanerEvent;
import org.gluu.service.cdi.event.Scheduled;
import org.gluu.service.timer.event.TimerEvent;
import org.gluu.service.timer.schedule.TimerSchedule;
import org.slf4j.Logger;

import com.google.common.base.Stopwatch;
import com.google.common.collect.Maps;

/**
 * @author Yuriy Movchan Date: 05/13/2020
 */
@ApplicationScoped
@Named
public class CleanerTimer {

	public final static int BATCH_SIZE = 1000;
	private final static int DEFAULT_INTERVAL = 30; // 30 seconds

	@Inject
	private Logger log;

	@Inject
	private PersistenceEntryManager entryManager;

	@Inject
	private StaticConfiguration staticConfiguration;

	@Inject
	private AppConfiguration appConfiguration;

	@Inject
	private AuthenticationPersistenceService authenticationPersistenceService;

	@Inject
	private RegistrationPersistenceService registrationPersistenceService;

	@Inject
	private Event<TimerEvent> cleanerEvent;

	private long lastFinishedTime;

	private AtomicBoolean isActive;

	public void initTimer() {
		log.debug("Initializing Cleaner Timer");
		this.isActive = new AtomicBoolean(false);

		// Schedule to start cleaner every 1 minute
		cleanerEvent.fire(
				new TimerEvent(new TimerSchedule(DEFAULT_INTERVAL, DEFAULT_INTERVAL), new CleanerEvent(), Scheduled.Literal.INSTANCE));

		this.lastFinishedTime = System.currentTimeMillis();
	}

	@Asynchronous
	public void process(@Observes @Scheduled CleanerEvent cleanerEvent) {
		if (this.isActive.get()) {
			return;
		}

		if (!this.isActive.compareAndSet(false, true)) {
			return;
		}

		try {
			processImpl();
		} finally {
			this.isActive.set(false);
		}
	}

	private boolean isStartProcess() {
		int interval = appConfiguration.getCleanServiceInterval();
		if (interval < 0) {
			log.info("Cleaner Timer is disabled.");
			log.warn("Cleaner Timer Interval (cleanServiceInterval in oxauth configuration) is negative which turns OFF internal clean up by the server. Please set it to positive value if you wish internal clean up timer run.");
			return false;
		}

		long cleaningInterval = interval * 1000;

		long timeDiffrence = System.currentTimeMillis() - this.lastFinishedTime;

		return timeDiffrence >= cleaningInterval;
	}

    public void processImpl() {
        try {
            if (!isStartProcess()) {
                log.trace("Starting conditions aren't reached");
                return;
            }

            int chunkSize = appConfiguration.getCleanServiceBatchChunkSize();
            if (chunkSize <= 0)
                chunkSize = BATCH_SIZE;

            Date now = new Date();

            final Set<String> processedBaseDns = new HashSet<>();
            for (Map.Entry<String, Class<?>> baseDn : createCleanServiceBaseDns().entrySet()) {
                final String processedKey = createProcessedKey(baseDn);
                if (entryManager.hasExpirationSupport(baseDn.getKey()) || processedBaseDns.contains(processedKey)) {
                    continue;
                }

                processedBaseDns.add(processedKey);

                if (log.isDebugEnabled())
                    log.debug("Start clean up for baseDn: {}, class: {}", baseDn.getValue(), baseDn.getValue());

                final Stopwatch started = Stopwatch.createStarted();

                int removed = cleanup(baseDn, now, chunkSize);

                if (log.isDebugEnabled())
                    log.debug("Finished clean up for baseDn: {}, takes: {}ms, removed items: {}", baseDn, started.elapsed(TimeUnit.MILLISECONDS), removed);
            }

            // Process sub-branches
            String baseDn = staticConfiguration.getBaseDn().getPeople();
            if (log.isDebugEnabled())
                log.debug("Start clean up for baseDn: {}", baseDn);

            final Stopwatch started = Stopwatch.createStarted();

            int removed = cleanupBranches(baseDn, now, chunkSize);

            if (log.isDebugEnabled())
                log.debug("Finished clean up for baseDn: {}, takes: {}ms, removed items: {}", baseDn, started.elapsed(TimeUnit.MILLISECONDS), removed);

			this.lastFinishedTime = System.currentTimeMillis();
        } catch (Exception e) {
            log.error("Failed to process clean up.", e);
        }
    }

    private static String createProcessedKey(Map.Entry<String, Class<?>> baseDn) {
        return baseDn.getKey() + "_" + (baseDn.getValue() == null ? "" : baseDn.getValue().getSimpleName());
    }

    private Map<String, Class<?>> createCleanServiceBaseDns() {

        final Map<String, Class<?>> cleanServiceBaseDns = Maps.newHashMap();

        cleanServiceBaseDns.put(staticConfiguration.getBaseDn().getFido2Attestation(), Fido2RegistrationEntry.class);
        cleanServiceBaseDns.put(staticConfiguration.getBaseDn().getFido2Assertion(), Fido2AuthenticationEntry.class);
        cleanServiceBaseDns.put(staticConfiguration.getBaseDn().getPeople(), Fido2RegistrationEntry.class);
        cleanServiceBaseDns.put(staticConfiguration.getBaseDn().getPeople(), Fido2AuthenticationEntry.class);

        return cleanServiceBaseDns;
    }

    public int cleanup(final Map.Entry<String, Class<?>> baseDn, final Date now, final int batchSize) {
        try {
            Filter filter = Filter.createANDFilter(
                    Filter.createEqualityFilter("del", true),
                    Filter.createLessOrEqualFilter("exp", entryManager.encodeTime(baseDn.getKey(), now)));

            int removedCount = entryManager.remove(baseDn.getKey(), baseDn.getValue(), filter, batchSize);
            log.trace("Removed {} entries from {}", removedCount, baseDn.getKey());
            return removedCount;
        } catch (Exception e) {
            log.error("Failed to perform clean up.", e);
        }

        return 0;
    }
    
    public int cleanupBranches(String branchDn, Date now, int batchSize) {
        try {
	        // Cleaning branches entries
			if (entryManager.hasExpirationSupport(branchDn) || !entryManager.hasBranchesSupport(branchDn)) {
				return 0;
			}

	        // Cleaning empty branches
			Filter filter = Filter.createANDFilter(
					Filter.createORFilter(Filter.createEqualityFilter("ou", "fido2_register"),
							Filter.createEqualityFilter("ou", "fido2_auth")),
					Filter.createORFilter(Filter.createEqualityFilter("numsubordinates", "0"),
							Filter.createEqualityFilter("hasSubordinates", "FALSE")));
	
	        int removedCount = entryManager.remove(branchDn, SimpleBranch.class, filter, batchSize);
	        log.trace("Removed {} entries from {}", removedCount, branchDn);
	        return removedCount;
	    } catch (Exception e) {
	        log.error("Failed to perform clean up.", e);
	    }

        return 0;
    }

}
