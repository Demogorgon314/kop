package io.streamnative.pulsar.handlers.kop.security;


import static java.util.Objects.requireNonNull;
import java.security.Principal;
import lombok.Getter;
import org.apache.pulsar.common.naming.NamespaceName;

public class KafkaPrincipal implements Principal {

    public static final String USER_TYPE = "User";
    public final static org.apache.kafka.common.security.auth.KafkaPrincipal
            ANONYMOUS = new org.apache.kafka.common.security.auth.KafkaPrincipal(
            org.apache.kafka.common.security.auth.KafkaPrincipal.USER_TYPE, "ANONYMOUS");

    @Getter
    private final String principalType;

    @Getter
    private final NamespaceName namespaceName;

    @Getter
    private final String role;

    private final String name;

    private volatile boolean tokenAuthenticated;

    public KafkaPrincipal(String principalType, String name) {
        this.principalType = requireNonNull(principalType, "Principal type cannot be null");
        this.name = requireNonNull(name, "Principal name cannot be null");
        String[] parts = this.name.split("/");
        if (parts.length != 3) {
            throw new IllegalArgumentException("Invalid name '" + name + "', it should be in the format <tenant>/<namespace>");
        }
        namespaceName = NamespaceName.get(parts[0], parts[1]);
        role = parts[2];
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
        return "KafkaPrincipal{" +
                "principalType='" + principalType + '\'' +
                ", namespaceName=" + namespaceName +
                ", role='" + role + '\'' +
                ", name='" + name + '\'' +
                ", tokenAuthenticated=" + tokenAuthenticated +
                '}';
    }
}
