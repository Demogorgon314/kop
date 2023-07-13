/**
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.streamnative.pulsar.handlers.kop.security.kerberos;

import com.sun.security.auth.module.Krb5LoginModule;
import java.io.Closeable;
import java.io.IOException;
import java.util.Date;
import java.util.Random;
import java.util.Set;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.kerberos.KerberosTicket;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.experimental.Accessors;
import lombok.extern.slf4j.Slf4j;
import org.apache.kafka.common.security.authenticator.AbstractLogin;
import org.apache.kafka.common.utils.Shell;

/**
 * A simple migration of org.apache.kafka.common.security.kerberos.KerberosLogin.
 */
@RequiredArgsConstructor
@Slf4j
public class KerberosLogin implements Closeable {

    private static volatile KerberosLogin instance;

    // The "sasl.kerberos.ticket.renew.window.factor" config in Kafka
    private static final double SASL_KERBEROS_TICKET_RENEW_WINDOW_FACTOR = 0.8;
    // The "sasl.kerberos.ticket.renew.jitter" config in Kafka
    private static final double SASL_KERBEROS_TICKET_RENEW_JITTER = 0.05;
    // The "sasl.kerberos.min.time.before.relogin" config in Kafka
    private static final long SASL_KERBEROS_MIN_TIME_BEFORE_RELOGIN = 60000;
    // The "sasl.kerberos.kinit.cmd" config
    private static final String SASL_KERBEROS_KINIT_CMD = "/usr/bin/kinit";

    private static final Random RNG = new Random();

    private final CallbackHandler loginCallbackHandler;
    private final Configuration configuration;
    private final String sectionName;
    private LoginContext loginContext;
    @Accessors(fluent = true)
    @Getter
    private Subject subject;
    private volatile boolean isUsingTicketCache;
    private String principal;
    private Thread t;
    private long lastLogin;

    public static KerberosLogin acquire(final String sectionName) throws LoginException {
        synchronized (KerberosLogin.class) {
            if (instance == null) {
                instance = new KerberosLogin(sectionName);
                instance.login();
            }
            return instance;
        }
    }

    public static void release() {
        synchronized (KerberosLogin.class) {
            if (instance != null) {
                instance.close();
            }
        }
    }

    public KerberosLogin(final String sectionName) {
        this.loginCallbackHandler = new AbstractLogin.DefaultLoginCallbackHandler();
        this.configuration = Configuration.getConfiguration();
        this.sectionName = sectionName;
    }

    synchronized void login() throws LoginException {
        loginContext = new LoginContext(sectionName, null, loginCallbackHandler, configuration);
        loginContext.login();
        log.info("Successfully logged in.");
        subject = loginContext.getSubject();
        if (subject.getPrivateCredentials(KerberosTicket.class).isEmpty()) {
            throw new IllegalArgumentException("No KerberosTicket found in the private credentials");
        }

        AppConfigurationEntry[] entries = configuration.getAppConfigurationEntry(sectionName);
        AppConfigurationEntry krb5Entry = null;
        for (AppConfigurationEntry entry : entries) {
            if (entry.getLoginModuleName().equals(Krb5LoginModule.class.getName())) {
                krb5Entry = entry;
            }
        }
        if (krb5Entry == null) {
            throw new IllegalArgumentException("No " + Krb5LoginModule.class.getName() + " module is configured");
        }
        if (krb5Entry.getOptions().get("useTicketCache") != null) {
            isUsingTicketCache = krb5Entry.getOptions().get("useTicketCache").equals("true");
        } else {
            isUsingTicketCache = false;
        }
        if (krb5Entry.getOptions().get("principal") != null) {
            principal = (String) krb5Entry.getOptions().get("principal");
        } else {
            principal = null;
            throw new IllegalArgumentException("No principal is configured in the Krb5LoginModule");
        }

        if (log.isDebugEnabled()) {
            log.debug("[Principal={}]: It is a Kerberos ticket", principal);
        }

        // Refresh the Ticket Granting Ticket (TGT) periodically. How often to refresh is determined by the
        // TGT's existing expiry date and the configured minTimeBeforeRelogin.
        final String threadName = String.format("kafka-kerberos-refresh-thread-%s", principal);
        t = new Thread(() -> {
            log.info("[Principal={}]: TGT refresh thread started.", principal);
            while (true) {
                KerberosTicket tgt = getTGT();
                long now = System.currentTimeMillis();
                long nextRefresh;
                Date nextRefreshDate;
                if (tgt == null) {
                    nextRefresh = now + SASL_KERBEROS_MIN_TIME_BEFORE_RELOGIN;
                    nextRefreshDate = new Date(nextRefresh);
                    log.warn("[Principal={}]: No TGT found: will try again at {}", principal, nextRefreshDate);
                } else {
                    nextRefresh = getRefreshTime(tgt);
                    long expiry = tgt.getEndTime().getTime();
                    Date expiryDate = new Date(expiry);
                    if (isUsingTicketCache && tgt.getRenewTill() != null && tgt.getRenewTill().getTime() < expiry) {
                        log.warn("The TGT cannot be renewed beyond the next expiry date: {}. This process will not be "
                                        + "able to authenticate new SASL connections after that time (for example, it "
                                        + "will not be able to authenticate a new connection with a Kafka Broker). ",
                                expiryDate);
                        return;
                    }
                    if ((nextRefresh > expiry) || (SASL_KERBEROS_MIN_TIME_BEFORE_RELOGIN > expiry - now)) {
                        // expiry is before next scheduled refresh).
                        log.info("[Principal={}]: Refreshing now because expiry is before next scheduled refresh time.",
                                principal);
                        nextRefresh = now;
                    } else {
                        if (nextRefresh - now < SASL_KERBEROS_MIN_TIME_BEFORE_RELOGIN) {
                            // next scheduled refresh is sooner than (now + MIN_TIME_BEFORE_LOGIN).
                            Date until = new Date(nextRefresh);
                            Date newUntil = new Date(now + SASL_KERBEROS_MIN_TIME_BEFORE_RELOGIN);
                            log.warn("[Principal={}]: TGT refresh thread time adjusted from {} to {} since the former "
                                    + "is sooner than the minimum refresh interval ({} seconds) from now.",
                                    principal, until, newUntil, SASL_KERBEROS_MIN_TIME_BEFORE_RELOGIN / 1000);
                        }
                        nextRefresh = Math.max(nextRefresh, now + SASL_KERBEROS_MIN_TIME_BEFORE_RELOGIN);
                    }
                    nextRefreshDate = new Date(nextRefresh);
                    if (nextRefresh > expiry) {
                        log.error("[Principal={}]: Next refresh: {} is later than expiry {}. This may indicate a clock "
                                + "skew problem. Check that this host and the KDC hosts' clocks are in sync. Exiting "
                                + "refresh thread.", principal, nextRefreshDate, expiryDate);
                        return;
                    }
                }
                if (now < nextRefresh) {
                    Date until = new Date(nextRefresh);
                    log.info("[Principal={}]: TGT refresh sleeping until: {}", principal, until);
                    try {
                        Thread.sleep(nextRefresh - now);
                    } catch (InterruptedException ie) {
                        log.warn("[Principal={}]: TGT renewal thread has been interrupted and will exit.", principal);
                        return;
                    }
                } else {
                    log.error("[Principal={}]: NextRefresh: {} is in the past: exiting refresh thread. Check"
                            + " clock sync between this host and KDC - (KDC's clock is likely ahead of this host)."
                            + " Manual intervention will be required for this client to successfully authenticate."
                            + " Exiting refresh thread.", principal, nextRefreshDate);
                    return;
                }
                if (isUsingTicketCache) {
                    String kinitArgs = "-R";
                    int retry = 1;
                    while (true) {
                        try {
                            if (log.isDebugEnabled()) {
                                log.debug("[Principal={}]: Running ticket cache refresh command: {} {}",
                                        principal, SASL_KERBEROS_KINIT_CMD, kinitArgs);
                            }
                            Shell.execCommand(SASL_KERBEROS_KINIT_CMD, kinitArgs);
                        } catch (IOException e) {
                            if (retry > 0) {
                                log.warn("[Principal={}]: Error when trying to re-Login, but will retry.",
                                        principal, e);
                                retry--;
                                try {
                                    Thread.sleep(10 * 1000);
                                } catch (InterruptedException ie) {
                                    log.error("[Principal={}]: Interrupted while renewing TGT, exiting Login thread",
                                            principal);
                                    return;
                                }
                            } else {
                                log.warn("[Principal={}]: Could not renew TGT due to problem running shell command: '{}"
                                        + " {}'. Exiting refresh thread.",
                                        principal, SASL_KERBEROS_KINIT_CMD, kinitArgs, e);
                                return;
                            }
                        }
                    }
                }

                int retry = 1;
                while (true) {
                    try {
                        reLogin();
                    } catch (LoginException e) {
                        if (retry > 0) {
                            log.warn("[Principal={}]: Error when trying to re-Login, but will retry ", principal, e);
                            retry--;
                            try {
                                Thread.sleep(10 * 1000);
                            } catch (InterruptedException ie) {
                                log.error("[Principal={}]: Interrupted during login retry after LoginException:",
                                        principal, e);
                                return;
                            }
                        } else {
                            log.error("[Principal={}]: Could not refresh TGT.", principal, e);
                        }
                    }
                }
            }
        }, threadName);
        t.setDaemon(true);
        t.setUncaughtExceptionHandler((__, e) -> log.error("Uncaught exception in thread '{}':", threadName, e));
        t.start();
    }

    @Override
    public synchronized void close() {
        if ((t != null) && (t.isAlive())) {
            t.interrupt();
            try {
                t.join();
            } catch (InterruptedException e) {
                log.warn("[Principal={}]: Error while waiting for Login thread to shutdown.", principal, e);
                Thread.currentThread().interrupt();
            }
        }
    }

    private static String getServiceName(final AppConfigurationEntry[] configEntries) {
        for (AppConfigurationEntry entry : configEntries) {
            Object serviceName = entry.getOptions().get("serviceName");
            if (serviceName != null) {
                return (String) serviceName;
            }
        }
        throw new IllegalArgumentException("No serviceName defined");
    }

    private KerberosTicket getTGT() {
        Set<KerberosTicket> tickets = subject.getPrivateCredentials(KerberosTicket.class);
        for (KerberosTicket ticket : tickets) {
            KerberosPrincipal server = ticket.getServer();
            if (server.getName().equals("krbtgt/" + server.getRealm() + "@" + server.getRealm())) {
                if (log.isDebugEnabled()) {
                    log.debug("Found TGT with client principal '{}' and server principal '{}'.",
                            ticket.getClient().getName(), ticket.getServer().getName());
                }
                return ticket;
            }
        }
        return null;
    }

    private long getRefreshTime(KerberosTicket tgt) {
        long start = tgt.getStartTime().getTime();
        long expires = tgt.getEndTime().getTime();
        log.info("[Principal={}]: TGT valid starting at: {}", principal, tgt.getStartTime());
        log.info("[Principal={}]: TGT expires: {}", principal, tgt.getEndTime());
        long proposedRefresh = start + (long) ((expires - start)
                * (SASL_KERBEROS_TICKET_RENEW_WINDOW_FACTOR + (SASL_KERBEROS_TICKET_RENEW_JITTER * RNG.nextDouble())));

        if (proposedRefresh > expires) {
            // proposedRefresh is too far in the future: it's after ticket expires: simply return now.
            return System.currentTimeMillis();
        } else {
            return proposedRefresh;
        }
    }

    private synchronized void reLogin() throws LoginException {
        if (loginContext == null) {
            throw new LoginException("Login must be done first");
        }
        if (!hasSufficientTimeElapsed()) {
            return;
        }
        log.info("Initiating logout for {}", principal);
        // register most recent relogin attempt
        lastLogin = System.currentTimeMillis();
        // clear up the kerberos state. But the tokens are not cleared! As per
        // the Java kerberos login module code, only the kerberos credentials
        // are cleared. If previous logout succeeded but login failed, we shouldn't
        // logout again since duplicate logout causes NPE from Java 9 onwards.
        if (subject != null && !subject.getPrincipals().isEmpty()) {
            loginContext.logout();
        }
        // login and also update the subject field of this instance to
        // have the new credentials (pass it to the LoginContext constructor)
        loginContext = new LoginContext(sectionName, subject, null, configuration);
        log.info("Initiating re-login for {}", principal);
        loginContext.login();
    }

    private boolean hasSufficientTimeElapsed() {
        long now = System.currentTimeMillis();
        if (now - lastLogin < SASL_KERBEROS_MIN_TIME_BEFORE_RELOGIN) {
            log.warn("[Principal={}]: Not attempting to re-login since the last re-login was attempted less than {} "
                            + "seconds before.",
                    principal, SASL_KERBEROS_MIN_TIME_BEFORE_RELOGIN / 1000);
            return false;
        }
        return true;
    }
}
