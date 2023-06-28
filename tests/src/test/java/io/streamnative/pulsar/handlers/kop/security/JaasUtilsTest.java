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

import java.util.Collections;
import org.testng.Assert;
import org.testng.annotations.Test;

public class JaasUtilsTest {

    @Test
    public void testJaasSection() {
        JaasUtils.JaasSection kerberosJaas = new JaasUtils.JaasSection("KafkaServer",
                Collections.singletonList(new JaasUtils.Krb5Module("/tmp/server.keytab",
                        "kafka/kafka.example.com@EXAMPLE.COM", "kafka")));
        Assert.assertEquals(kerberosJaas.toString(), "KafkaServer {\n"
                + "  com.sun.security.auth.module.Krb5LoginModule required\n"
                + "  debug=true\n"
                + "  principal=\"kafka/kafka.example.com@EXAMPLE.COM\"\n"
                + "  storeKey=\"true\"\n"
                + "  keyTab=\"/tmp/server.keytab\"\n"
                + "  useKeyTab=\"true\"\n"
                + "  serviceName=\"kafka\";\n"
                + "}"
        );
    }
}
