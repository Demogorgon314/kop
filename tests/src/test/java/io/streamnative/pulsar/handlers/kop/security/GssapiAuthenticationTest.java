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

import static org.testng.Assert.assertThrows;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

import java.io.File;
import java.time.Duration;
import java.util.Collections;
import java.util.concurrent.ExecutionException;
import lombok.Cleanup;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.clients.producer.RecordMetadata;
import org.apache.kafka.common.errors.SaslAuthenticationException;
import org.apache.kafka.common.errors.TopicAuthorizationException;
import org.apache.pulsar.common.policies.data.AuthAction;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

public class GssapiAuthenticationTest extends GssapiAuthenticationTestBase {

    @BeforeClass
    @Override
    protected void setup() throws Exception {
        conf.setKopAuthorizationCacheRefreshMs(-1);
        super.internalSetup(null);
    }

    @AfterClass
    @Override
    public void cleanup() throws Exception {
        super.cleanup();
    }

    @Test
    public void testGrantPermission() throws Exception {
        final String topic = "test-grant-permission-" + System.currentTimeMillis();
        @Cleanup
        final KafkaProducer<String, String> producer = new KafkaProducer<>(gssapi(newKafkaProducerProperties()));
        try {
            producer.send(new ProducerRecord<>(topic, "value")).get();
            fail();
        } catch (ExecutionException e) {
            assertTrue(e.getCause() instanceof TopicAuthorizationException);
        }

        admin.namespaces().grantPermissionOnNamespace(NAMESPACE, JaasUtils.KAFKA_CLIENT_PRINCIPAL_UNQUALIFIED_NAME,
                Collections.singleton(AuthAction.produce));

        final RecordMetadata metadata = producer.send(new ProducerRecord<>(topic, "value")).get();
        @Cleanup
        final KafkaConsumer<String, String> consumer = new KafkaConsumer<>(gssapi(newKafkaConsumerProperties()));
        consumer.subscribe(Collections.singleton(topic));
        assertThrows(TopicAuthorizationException.class, () -> consumer.poll(Duration.ofSeconds(10)));

        admin.namespaces().grantPermissionOnNamespace(NAMESPACE, JaasUtils.KAFKA_CLIENT_PRINCIPAL_UNQUALIFIED_NAME,
                Collections.singleton(AuthAction.consume));
        receiveAndAssert(consumer, "value", metadata);
    }

    @Test
    public void testShortPrincipalName() throws Exception {
        final File keytabFile = TestUtils.tempFile();
        final String principal = "client2/localhost@EXAMPLE.COM";
        final String shortPrincipal = "client2";
        kdc.createPrincipal(keytabFile, principal);
        final String topic = "test-short-principal-name-" + System.currentTimeMillis();
        @Cleanup
        final KafkaProducer<String, String> producer = new KafkaProducer<>(
                gssapi(newKafkaProducerProperties(), keytabFile, principal));
        try {
            producer.send(new ProducerRecord<>(topic, "value")).get();
            fail();
        } catch (ExecutionException e) {
            assertTrue(e.getCause() instanceof TopicAuthorizationException);
        }

        admin.namespaces().grantPermissionOnNamespace(NAMESPACE, shortPrincipal,
                Collections.singleton(AuthAction.produce));
        producer.send(new ProducerRecord<>(topic, "value")).get();
    }

    @Test
    public void testInvalidPrincipalName() throws Exception {
        final File keytabFile = TestUtils.tempFile();
        final String principal = "kopclient@EXAMPLE.COM";
        final String shortPrincipal = "kopclient";
        kdc.createPrincipal(keytabFile, principal);
        admin.namespaces().grantPermissionOnNamespace(NAMESPACE, shortPrincipal,
                Collections.singleton(AuthAction.produce));
        @Cleanup
        final KafkaProducer<String, String> producer = new KafkaProducer<>(
                gssapi(newKafkaProducerProperties(), keytabFile, principal));
        try {
            producer.send(new ProducerRecord<>("test-invalid-principal-name", "value")).get();
            fail();
        } catch (ExecutionException e) {
            assertTrue(e.getCause() instanceof SaslAuthenticationException);
        }
    }
}
