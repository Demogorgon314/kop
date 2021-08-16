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


import static java.util.Objects.requireNonNull;

import java.security.Principal;
import lombok.Getter;


/**
 * KafkaPrincipal store client login info.
 */
public class KafkaPrincipal implements Principal {

    public static final String USER_TYPE = "User";

    @Getter
    private final String principalType;

    private final String name;

    private volatile boolean tokenAuthenticated;

    public KafkaPrincipal(String principalType, String name) {
        this.principalType = requireNonNull(principalType, "Principal type cannot be null");
        this.name = requireNonNull(name, "Principal name cannot be null");
    }

    @Override
    public String getName() {
        return name;
    }

    public void tokenAuthenticated(boolean tokenAuthenticated) {
        this.tokenAuthenticated = tokenAuthenticated;
    }

    public boolean tokenAuthenticated() {
        return tokenAuthenticated;
    }

    @Override
    public String toString() {
        return "KafkaPrincipal{"
                + "principalType='"
                + principalType + '\''
                + ", name='"
                + name + '\''
                + ", tokenAuthenticated="
                + tokenAuthenticated
                + '}';
    }
}
