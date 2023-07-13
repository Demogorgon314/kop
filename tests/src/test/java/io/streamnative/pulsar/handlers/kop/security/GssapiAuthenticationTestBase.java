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

import static org.testng.Assert.assertEquals;

import io.streamnative.pulsar.handlers.kop.KopProtocolHandlerTestBase;
import java.io.File;
import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.Properties;
import org.apache.kafka.clients.CommonClientConfigs;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.ConsumerRecords;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.clients.producer.RecordMetadata;
import org.apache.kafka.common.config.SaslConfigs;
import org.apache.kafka.common.security.auth.SecurityProtocol;
import org.apache.pulsar.broker.authentication.AuthenticationProviderSasl;
import org.apache.pulsar.client.impl.auth.AuthenticationSasl;

public abstract class GssapiAuthenticationTestBase extends KopProtocolHandlerTestBase {

    protected static final String NAMESPACE = "public/default";
    private static final List<String> KAFKA_SERVER_SASL_MECHANISMS =
            Collections.singletonList(SaslConfigs.GSSAPI_MECHANISM);
    private final SaslSetup saslSetup = new SaslSetup();
    protected MiniKdc kdc;

    protected void internalSetup(final Class<?> authorizationProvider) throws Exception {
        saslSetup.startSasl(saslSetup.jaasSections(KAFKA_SERVER_SASL_MECHANISMS, SaslConfigs.GSSAPI_MECHANISM));
        kdc = saslSetup.getKdc();
        // Enable Pulsar authentication, which iss actually unnecessary, however, the Pulsar authorization requires the
        // authentication is enabled.
        conf.setAuthenticationEnabled(true);
        conf.setAuthenticationProviders(Collections.singleton(AuthenticationProviderSasl.class.getName()));
        conf.setSaslJaasServerSectionName(JaasUtils.KAFKA_SERVER_CONTEXT_NAME);
        conf.setSaslJaasClientAllowedIds(".*client.*");
        conf.setBrokerClientAuthenticationPlugin(AuthenticationSasl.class.getName());
        conf.setBrokerClientAuthenticationParameters("{\"saslJaasClientSectionName\":\""
                + JaasUtils.KAFKA_CLIENT_CONTEXT_NAME + "\", \"serverType\":\""
                + JaasUtils.KAFKA_SERVER_PRINCIPAL_UNQUALIFIED_NAME + "\"}");
        conf.setSuperUserRoles(Collections.singleton(JaasUtils.KAFKA_CLIENT_PRINCIPAL));

        // Enable KoP authentication for Kerberos
        conf.setSaslAllowedMechanisms(Collections.singleton(SaslConfigs.GSSAPI_MECHANISM));
        conf.setKopKerberosClientAllowedIds("client.*"); // different from saslJaasClientAllowedIds

        // Enable authorization
        conf.setAuthorizationEnabled(true);
        if (authorizationProvider != null) {
            conf.setAuthorizationProvider(authorizationProvider.getName());
        }

        super.internalSetup();
    }

    @Override
    protected void cleanup() throws Exception {
        saslSetup.closeSasl();
        super.internalCleanup();
    }


    protected Properties gssapi(final Properties props, final File keytabFile, final String principal) {
        props.put(CommonClientConfigs.SECURITY_PROTOCOL_CONFIG, SecurityProtocol.SASL_PLAINTEXT.name());
        props.put(SaslConfigs.SASL_MECHANISM, SaslConfigs.GSSAPI_MECHANISM);
        props.put(SaslConfigs.SASL_JAAS_CONFIG, JaasUtils.gssapiJaasClientLoginModule(keytabFile, principal));
        props.put(SaslConfigs.SASL_KERBEROS_SERVICE_NAME, JaasUtils.SERVICE_NAME);
        props.put(CommonClientConfigs.REQUEST_TIMEOUT_MS_CONFIG, "10000");
        return props;
    }

    protected Properties gssapi(final Properties props) {
        return gssapi(props, saslSetup.clientKeytabFile, JaasUtils.KAFKA_CLIENT_PRINCIPAL);
    }

    protected void receiveAndAssert(final KafkaConsumer<String, String> consumer, final String value,
                                    final RecordMetadata metadata) {
        for (int i = 0; i < 100; i++) {
            final ConsumerRecords<String, String> records = consumer.poll(Duration.ofMillis(100));
            if (!records.isEmpty()) {
                final ConsumerRecord<String, String> record = records.iterator().next();
                assertEquals(record.value(), value);
                assertEquals(record.topic(), metadata.topic());
                assertEquals(record.partition(), metadata.partition());
                assertEquals(record.offset(), metadata.offset());
                assertEquals(record.timestamp(), metadata.timestamp());
                return;
            }
        }
        throw new IllegalStateException("No records available");
    }
}
