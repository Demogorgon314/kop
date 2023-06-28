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
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import javax.annotation.Nullable;
import javax.security.auth.login.Configuration;
import org.apache.kafka.common.config.SaslConfigs;
import org.apache.kerby.kerberos.kerb.KrbException;

public class SaslSetup {

    private final Properties kdcConf = MiniKdc.createConfig();
    private final File workDir = TestUtils.tempDirectory();
    private File serverKeytabFile;
    private File clientKeytabFile;
    private MiniKdc kdc;

    public void startSasl(final List<JaasUtils.JaasSection> jaasSections) throws KrbException, IOException {
        final boolean hasKerberos = jaasSections.stream().anyMatch(jaasSection -> jaasSection.modules().stream()
                .anyMatch(module -> module instanceof JaasUtils.Krb5Module));
        if (hasKerberos) {
            // Initialize Kerberos
            initializeKerberos();
        }
        writeJaasConfigurationsToFile(jaasSections);
    }

    public void closeSasl() {
        if (kdc != null) {
            kdc.stop();
        }
        System.clearProperty(JaasUtils.JAVA_LOGIN_CONFIG_PARAM);
        Configuration.setConfiguration(null);
    }

    public List<JaasUtils.JaasSection> jaasSections(final List<String> kafkaServerSaslMechanisms,
                                                    @Nullable final String kafkaClientSaslMechanism) {
        if (kafkaServerSaslMechanisms.contains(SaslConfigs.GSSAPI_MECHANISM)
                || SaslConfigs.GSSAPI_MECHANISM.equals(kafkaClientSaslMechanism)) {
            maybeCreateEmptyKeytabFiles();
        }
        final List<JaasUtils.JaasSection> jaasSections = new ArrayList<>();
        jaasSections.add(JaasUtils.kafkaServerSection(
                JaasUtils.KAFKA_SERVER_CONTEXT_NAME, kafkaServerSaslMechanisms, serverKeytabFile));
        jaasSections.add(JaasUtils.kafkaClientSection(kafkaClientSaslMechanism, clientKeytabFile));
        return jaasSections;
    }

    private void initializeKerberos() throws KrbException, IOException {
        maybeCreateEmptyKeytabFiles();
        kdc = new MiniKdc(kdcConf, workDir);
        kdc.start();
        kdc.createPrincipal(serverKeytabFile, JaasUtils.KAFKA_SERVER_PRINCIPAL_UNQUALIFIED_NAME + "/localhost");
        kdc.createPrincipal(clientKeytabFile, JaasUtils.KAFKA_CLIENT_PRINCIPAL_UNQUALIFIED_NAME,
                JaasUtils.KAFKA_CLIENT_PRINCIPAL_UNQUALIFIED_NAME2);
    }

    private void maybeCreateEmptyKeytabFiles() {
        if (serverKeytabFile == null) {
            serverKeytabFile = TestUtils.tempFile();
        }
        if (clientKeytabFile == null) {
            clientKeytabFile = TestUtils.tempFile();
        }
    }

    private void writeJaasConfigurationsToFile(final List<JaasUtils.JaasSection> jaasSections) throws IOException {
        final File file = TestUtils.writeJaasContextsToFile(jaasSections);
        System.setProperty(JaasUtils.JAVA_LOGIN_CONFIG_PARAM, file.getAbsolutePath());
        // This will cause a reload of the Configuration singleton when `getConfiguration` is called
        Configuration.setConfiguration(null);
    }
}
