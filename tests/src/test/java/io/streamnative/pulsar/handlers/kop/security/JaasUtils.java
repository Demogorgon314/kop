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
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import javax.annotation.Nullable;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.experimental.Accessors;
import org.apache.kafka.common.config.SaslConfigs;

public class JaasUtils {

    public static final String JAVA_LOGIN_CONFIG_PARAM = "java.security.auth.login.config";
    public static final String KAFKA_SERVER_PRINCIPAL_UNQUALIFIED_NAME = "kafka";
    public static final String KAFKA_SERVER_PRINCIPAL =
            KAFKA_SERVER_PRINCIPAL_UNQUALIFIED_NAME + "/localhost@EXAMPLE.COM";
    public static final String KAFKA_SERVER_CONTEXT_NAME = "KafkaServer";
    public static final String KAFKA_CLIENT_PRINCIPAL_UNQUALIFIED_NAME = "client";
    //public static final String KAFKA_CLIENT_PRINCIPAL = KAFKA_CLIENT_PRINCIPAL_UNQUALIFIED_NAME + "@EXAMPLE.COM";
    public static final String KAFKA_CLIENT_PRINCIPAL_UNQUALIFIED_NAME2 = "client2";
    public static final String KAFKA_CLIENT_PRINCIPAL2 = KAFKA_CLIENT_PRINCIPAL_UNQUALIFIED_NAME2 + "@EXAMPLE.COM";
    private static final String KAFKA_CLIENT_CONTEXT_NAME = "KafkaClient";

    private static final String SERVICE_NAME = "kafka";

    public static JaasSection kafkaServerSection(final String contextName, final List<String> mechanisms,
                                                 final File keytabLocation) {
        return new JaasSection(contextName, mechanisms.stream().map(mechanism -> {
            if (mechanism.equals(SaslConfigs.GSSAPI_MECHANISM)) {
                return new Krb5Module(keytabLocation.getAbsolutePath(), KAFKA_SERVER_PRINCIPAL, SERVICE_NAME);
            } else {
                throw new IllegalArgumentException("Unsupported server mechanism " + mechanism);
            }
        }).collect(Collectors.toList()));
    }

    public static JaasSection kafkaClientSection(@Nullable final String mechanism,
                                                 @Nullable final File keytabLocation) {
        return new JaasSection(KAFKA_CLIENT_CONTEXT_NAME, Optional.ofNullable(mechanism).map(m -> {
            if (mechanism.equals(SaslConfigs.GSSAPI_MECHANISM)) {
                if (keytabLocation == null) {
                    throw new IllegalArgumentException("Keytab location not specified for GSSAPI");
                }
                return Collections.singletonList((JaasModule) new Krb5Module(keytabLocation.getAbsolutePath(),
                        KAFKA_CLIENT_PRINCIPAL2, SERVICE_NAME));
            } else {
                throw new IllegalArgumentException("Unsupported client mechanism " + mechanism);
            }
        }).orElse(Collections.emptyList()));
    }


    public abstract static class JaasModule {

        abstract String name();

        abstract boolean debug();

        abstract Map<String, String> entries();

        @Override
        public String toString() {
            return String.format("%s required\n"
                    + "  debug=%b\n"
                    + "  %s;", name(), debug(), String.join("\n  ", entries().entrySet().stream()
                    .map(e -> String.format("%s=\"%s\"", e.getKey(), e.getValue())).collect(Collectors.toList()))
            );
        }
    }

    @RequiredArgsConstructor
    public static class Krb5Module extends JaasModule {
        private final String keyTab;
        private final String principal;
        private final String serviceName;

        @Override
        String name() {
            return "com.sun.security.auth.module.Krb5LoginModule";
        }

        @Override
        boolean debug() {
            return true;
        }

        @Override
        Map<String, String> entries() {
            final Map<String, String> map = new HashMap<>();
            map.put("useKeyTab", "true");
            map.put("storeKey", "true");
            map.put("keyTab", keyTab);
            map.put("principal", principal);
            map.put("serviceName", serviceName);
            return map;
        }
    }

    @AllArgsConstructor
    public static class JaasSection {

        private final String contextName;
        @Accessors(fluent = true)
        @Getter
        private final List<JaasModule> modules;

        @Override
        public String toString() {
            return String.format("%s {\n  %s\n}", contextName, String.join("\n    ",
                    modules.stream().map(JaasModule::toString).collect(Collectors.toList())));
        }
    }
}
