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
package io.streamnative.pulsar.handlers.kop.security;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashSet;
import java.util.Locale;
import java.util.Properties;
import java.util.Set;
import lombok.extern.slf4j.Slf4j;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.server.KdcConfigKey;
import org.apache.kerby.kerberos.kerb.server.SimpleKdcServer;
import org.apache.kerby.util.IOUtil;
import org.apache.kerby.util.NetworkUtil;

@Slf4j
public class MiniKdc {


    public static final String ORG_NAME = "org.name";
    public static final String ORG_DOMAIN = "org.domain";
    public static final String KDC_BIND_ADDRESS = "kdc.bind.address";
    public static final String KDC_PORT = "kdc.port";
    public static final String INSTANCE = "instance";
    public static final String MAX_TICKET_LIFETIME = "max.ticket.lifetime";
    public static final String MIN_TICKET_LIFETIME = "min.ticket.lifetime";
    public static final String MAX_RENEWABLE_LIFETIME = "max.renewable.lifetime";
    public static final String TRANSPORT = "transport";
    public static final String DEBUG = "debug";

    private static final Set<String> PROPERTIES = new HashSet<>();
    private static final Properties DEFAULT_CONFIG = new Properties();

    static {
        PROPERTIES.add(ORG_NAME);
        PROPERTIES.add(ORG_DOMAIN);
        PROPERTIES.add(KDC_BIND_ADDRESS);
        PROPERTIES.add(KDC_PORT);
        PROPERTIES.add(INSTANCE);
        PROPERTIES.add(TRANSPORT);
        PROPERTIES.add(MAX_TICKET_LIFETIME);
        PROPERTIES.add(MAX_RENEWABLE_LIFETIME);

        DEFAULT_CONFIG.setProperty(KDC_BIND_ADDRESS, "localhost");
        DEFAULT_CONFIG.setProperty(KDC_PORT, "0");
        DEFAULT_CONFIG.setProperty(INSTANCE, "DefaultKdcServer");
        DEFAULT_CONFIG.setProperty(ORG_NAME, "Example");
        DEFAULT_CONFIG.setProperty(ORG_DOMAIN, "COM");
        DEFAULT_CONFIG.setProperty(TRANSPORT, "TCP");
        DEFAULT_CONFIG.setProperty(MAX_TICKET_LIFETIME, "86400000");
        DEFAULT_CONFIG.setProperty(MAX_RENEWABLE_LIFETIME, "604800000");
        DEFAULT_CONFIG.setProperty(DEBUG, "false");
    };

    private final Properties conf;
    private final File workDir;
    private SimpleKdcServer simpleKdc;
    private final int port;
    private final String realm;
    private final File krb5conf;
    private final String transport;

    public MiniKdc(Properties conf, File workDir) {
        if (!conf.keySet().containsAll(PROPERTIES)) {
            Set<Object> missingProperties = new HashSet<>(PROPERTIES);
            missingProperties.removeAll(conf.keySet());
            throw new IllegalArgumentException("Missing configuration properties: " + missingProperties);
        }
        log.info("MiniKdc configuration:");
        conf.forEach((key, value) -> log.info("  {}: {}", key, value));
        this.conf = conf;
        this.workDir = workDir;
        int port = Integer.parseInt(conf.getProperty(KDC_PORT));
        this.port = (port == 0) ? NetworkUtil.getServerPort() : port;
        this.realm = conf.getProperty(ORG_NAME).toUpperCase(Locale.ENGLISH) + "."
                + conf.getProperty(ORG_DOMAIN).toUpperCase(Locale.ENGLISH);
        this.krb5conf = new File(workDir, "krb5.conf");
        this.krb5conf.deleteOnExit();
        this.transport = conf.getProperty(TRANSPORT);
    }

    public synchronized void start() throws KrbException, IOException {
        if (simpleKdc != null) {
            throw new RuntimeException("Already started");
        }
        simpleKdc = new SimpleKdcServer();
        prepareKdcServer();
        simpleKdc.init();
        resetDefaultRealm();
        simpleKdc.start();
        log.info("MiniKdc started");
    }

    private void resetDefaultRealm() throws IOException {
        try (InputStream templateResource = new FileInputStream(krb5conf.getAbsolutePath())) {
            String content = IOUtil.readInput(templateResource);
            content = content.replaceAll("default_realm = .*\n",
                    "default_realm = " + realm + "\n");
            IOUtil.writeFile(content, krb5conf);
        }
    }

    private void prepareKdcServer() {
        simpleKdc.setWorkDir(workDir);
        simpleKdc.setKdcHost(conf.getProperty(KDC_BIND_ADDRESS));
        simpleKdc.setKdcRealm(realm);
        if (transport.trim().equals("TCP")) {
            simpleKdc.setKdcTcpPort(port);
            simpleKdc.setAllowUdp(false);
        } else if (transport.trim().equals("UDP")) {
            simpleKdc.setKdcUdpPort(port);
            simpleKdc.setAllowTcp(false);
        } else {
            throw new IllegalArgumentException("Invalid transport: " + transport);
        }
        simpleKdc.getKdcConfig().setString(KdcConfigKey.KDC_SERVICE_NAME, conf.getProperty(INSTANCE));
        simpleKdc.getKdcConfig().setLong(KdcConfigKey.MAXIMUM_TICKET_LIFETIME,
                Long.parseLong(conf.getProperty(MAX_TICKET_LIFETIME)));
    }

    public synchronized void stop() {
        if (simpleKdc != null) {
            try {
                simpleKdc.stop();
            } catch (KrbException e) {
                log.warn("Failed to stop KDC: {}", e.getMessage());
            }
        }
        log.info("MiniKdc stopped.");
    }

    public synchronized void createPrincipal(File keytabFile, String... principals) throws KrbException {
        simpleKdc.createPrincipals(principals);
        if (keytabFile.exists() && !keytabFile.delete()) {
            throw new RuntimeException("Failed to delete keytab file: " + keytabFile);
        }
        for (String principal : principals) {
            simpleKdc.getKadmin().exportKeytab(keytabFile, principal);
        }
    }

    public static Properties createConfig() {
        return (Properties) DEFAULT_CONFIG.clone();
    }
}
