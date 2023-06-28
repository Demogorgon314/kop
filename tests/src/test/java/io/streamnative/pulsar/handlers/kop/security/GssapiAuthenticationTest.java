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

import io.streamnative.pulsar.handlers.kop.KopProtocolHandlerTestBase;
import java.util.Collections;
import java.util.List;
import org.apache.kafka.common.config.SaslConfigs;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

public class GssapiAuthenticationTest extends KopProtocolHandlerTestBase {

    private static final List<String> KAFKA_SERVER_SASL_MECHANISMS =
            Collections.singletonList(SaslConfigs.GSSAPI_MECHANISM);
    private static final String KAFKA_CLIENT_SASL_MECHANISM = SaslConfigs.GSSAPI_MECHANISM;
    private final SaslSetup saslSetup = new SaslSetup();

    @BeforeClass
    @Override
    protected void setup() throws Exception {
        saslSetup.startSasl(saslSetup.jaasSections(KAFKA_SERVER_SASL_MECHANISMS, KAFKA_CLIENT_SASL_MECHANISM));
        super.internalSetup();
    }

    @AfterClass
    @Override
    protected void cleanup() throws Exception {
        super.internalCleanup();
    }

    // TODO: Remove it after adding the real tests. This test is only used to test MiniKdc has started.
    @Test
    public void test() {
    }
}
