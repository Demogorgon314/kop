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

import java.io.IOException;
import java.util.regex.Pattern;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.RealmCallback;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@AllArgsConstructor
@Slf4j
public class KerberosCallbackHandler implements CallbackHandler {

    private final Pattern allowedIdsPattern;

    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        for (Callback callback : callbacks) {
            if (callback instanceof RealmCallback) {
                RealmCallback realmCallback = (RealmCallback) callback;
                realmCallback.setText(realmCallback.getDefaultText());
            } else if (callback instanceof AuthorizeCallback) {
                AuthorizeCallback authorizeCallback = (AuthorizeCallback) callback;
                String authenticationID = authorizeCallback.getAuthenticationID();
                if (!allowedIdsPattern.matcher(authenticationID).matches()) {
                    authorizeCallback.setAuthorized(false);
                    log.warn("Forbidden access to client: authenticationID {}, which does not match regex \"{}\"",
                            authenticationID, allowedIdsPattern);
                    return;
                }
                log.info("Successfully authenticated client: authenticationID={}; authorizationID={}.",
                        authenticationID, authorizeCallback.getAuthorizationID());
                authorizeCallback.setAuthorized(true);
                authorizeCallback.setAuthorizedID(authenticationID);
            } else {
                throw new UnsupportedCallbackException(callback);
            }
        }
    }
}
