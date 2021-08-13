package io.streamnative.pulsar.handlers.kop.security.auth;


import lombok.Getter;
import org.apache.kafka.common.resource.ResourceType;

public class Resource {
    @Getter
    private final ResourceType resourceType;
    @Getter
    private final String name;

    public Resource(ResourceType resourceType, String name) {
        this.resourceType = resourceType;
        this.name = name;
    }

    public static Resource of(ResourceType resourceType, String name) {
        return new Resource(resourceType, name);
    }


}
