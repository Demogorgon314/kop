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

import io.streamnative.pulsar.handlers.kop.security.auth.KafkaMockAuthorizationProvider;
import java.io.File;
import java.time.Duration;
import java.util.Collections;
import java.util.concurrent.ExecutionException;
import lombok.Cleanup;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.clients.producer.RecordMetadata;
import org.apache.kafka.common.errors.TopicAuthorizationException;
import org.apache.pulsar.common.policies.data.AuthAction;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

public class GsspiCustomAuthorizerTest extends GssapiAuthenticationTestBase {

    public static class MockAuthorizationProvider extends KafkaMockAuthorizationProvider {

        @Override
        public boolean roleAuthorized(String role) {
            return role.equals(JaasUtils.KAFKA_CLIENT_PRINCIPAL) // for Pulsar admin or client
                    || role.equals(JaasUtils.KAFKA_CLIENT_PRINCIPAL_UNQUALIFIED_NAME); // for Kafka client
        }
    }

    @BeforeClass
    @Override
    public void setup() throws Exception {
        super.internalSetup(MockAuthorizationProvider.class);
    }

    @AfterClass
    @Override
    public void cleanup() throws Exception {
        super.cleanup();
    }

    @Test
    public void testAuthorizationSuccess() throws Exception {
        final String topic = "test-authorization-success-" + System.currentTimeMillis();
        @Cleanup
        final KafkaProducer<String, String> producer = new KafkaProducer<>(gssapi(newKafkaProducerProperties()));
        @Cleanup
        final KafkaConsumer<String, String> consumer = new KafkaConsumer<>(gssapi(newKafkaConsumerProperties()));
        consumer.subscribe(Collections.singleton(topic));
        final RecordMetadata metadata = producer.send(new ProducerRecord<>(topic, "value0")).get();
        receiveAndAssert(consumer, "value0", metadata);
    }

    @Test
    public void testAuthorizationFailure() throws Exception {
        final File keytabFile = TestUtils.tempFile();
        final String principal = "client2/localhost@EXAMPLE.COM";
        kdc.createPrincipal(keytabFile, principal);
        admin.namespaces().grantPermissionOnNamespace(NAMESPACE, "client2",
                Collections.singleton(AuthAction.produce));

        final String topic = "test-authorization-failure-" + System.currentTimeMillis();
        @Cleanup
        final KafkaProducer<String, String> producer = new KafkaProducer<>(
                gssapi(newKafkaProducerProperties(), keytabFile, principal));
        try {
            producer.send(new ProducerRecord<>(topic, "value")).get();
            fail();
        } catch (ExecutionException e) {
            assertTrue(e.getCause() instanceof TopicAuthorizationException);
        }
        @Cleanup
        final KafkaConsumer<String, String> consumer = new KafkaConsumer<>(
                gssapi(newKafkaConsumerProperties(), keytabFile, principal));
        consumer.subscribe(Collections.singleton(topic));
        assertThrows(TopicAuthorizationException.class, () -> consumer.poll(Duration.ofSeconds(10)));
    }
}
