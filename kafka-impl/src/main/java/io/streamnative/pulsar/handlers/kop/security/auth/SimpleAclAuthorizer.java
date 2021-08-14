package io.streamnative.pulsar.handlers.kop.security.auth;


import io.streamnative.pulsar.handlers.kop.security.KafkaPrincipal;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import lombok.extern.slf4j.Slf4j;
import org.apache.kafka.common.resource.ResourceType;
import org.apache.pulsar.broker.PulsarService;
import org.apache.pulsar.common.naming.TopicName;
import org.apache.pulsar.common.policies.data.AuthAction;

@Slf4j
public class SimpleAclAuthorizer implements Authorizer {

    private static final String POLICY_ROOT = "/admin/policies/";

    private final PulsarService pulsarService;

    public SimpleAclAuthorizer(PulsarService pulsarService) {
        this.pulsarService = pulsarService;
    }

    public CompletableFuture<Boolean> authorize(KafkaPrincipal principal, AuthAction action, Resource resource) {
        CompletableFuture<Boolean> permissionFuture = new CompletableFuture<>();
        String path;
        if (resource != null && resource.getResourceType() == ResourceType.TOPIC) {
            path = POLICY_ROOT + TopicName.get(resource.getName()).getNamespace();
        } else {
            path = POLICY_ROOT + principal.getNamespaceName().toString();
        }
        try {
            pulsarService
                    .getPulsarResources()
                    .getNamespaceResources()
                    .getAsync(path)
                    .thenAccept(policies -> {
                        if (!policies.isPresent()) {
                            if (log.isDebugEnabled()) {
                                log.debug("Policies node couldn't be found for namespace : {}", principal);
                            }
                        } else {
                            String role = principal.getRole();
                            if (resource != null) {
                                if (resource.getResourceType() == ResourceType.TOPIC) {
                                    Map<String, Set<AuthAction>> topicRoles = policies.get().auth_policies.getTopicAuthentication()
                                            .get(resource.getName());
                                    if (topicRoles != null && role != null) {
                                        // Topic has custom policy
                                        Set<AuthAction> topicActions = topicRoles.get(role);
                                        if (topicActions != null && topicActions.contains(action)) {
                                            permissionFuture.complete(true);
                                            return;
                                        }
                                    }
                                }

                                if (resource.getResourceType() == ResourceType.GROUP) {
                                    Set<String> roles = policies.get().auth_policies
                                            .getSubscriptionAuthentication().get(resource.getName());
                                    if (roles != null && !roles.isEmpty() && !roles.contains(role)) {
                                        log.warn("[{}] is not authorized to subscribe on {}-{}", role, principal.getNamespaceName(), resource.getName());
                                        permissionFuture.complete(false);
                                        return;
                                    }
                                }
                            }

                            Map<String, Set<AuthAction>> namespaceRoles = policies.get().auth_policies
                                    .getNamespaceAuthentication();
                            Set<AuthAction> namespaceActions = namespaceRoles.get(role);
                            if (namespaceActions != null && namespaceActions.contains(action)) {
                                permissionFuture.complete(true);
                                return;
                            }
                        }
                        permissionFuture.complete(false);
                    }).exceptionally(ex -> {
                        log.warn("Client with Principal - {} failed to get permissions for resource - {}. {}", principal, resource,
                                ex.getMessage());
                        permissionFuture.completeExceptionally(ex);
                        return null;
                    });
        } catch (Exception e) {
            log.warn("Client with Principal - {} failed to get permissions for resource - {}. {}", principal, resource,
                    e.getMessage());
            permissionFuture.completeExceptionally(e);
        }
        return permissionFuture;
    }


    public CompletableFuture<Boolean> canLookup(KafkaPrincipal principal, Resource resource) {
        CompletableFuture<Boolean> canLookupFuture = new CompletableFuture<>();
        try {
            pulsarService
                    .getPulsarResources()
                    .getNamespaceResources()
                    .getAsync(POLICY_ROOT + TopicName.get(resource.getName()).getNamespace())
                    .thenAccept(policies -> {
                        if (!policies.isPresent()) {
                            if (log.isDebugEnabled()) {
                                log.debug("Policies node couldn't be found for namespace : {}", principal);
                            }
                        } else {
                            String role = principal.getRole();
                            Map<String, Set<AuthAction>> namespaceRoles = policies.get().auth_policies
                                    .getNamespaceAuthentication();
                            Set<AuthAction> namespaceActions = namespaceRoles.get(role);
                            if (namespaceActions != null && !namespaceActions.isEmpty()) {
                                canLookupFuture.complete(true);
                                return;
                            }
                            Map<String, Set<AuthAction>> topicRoles = policies.get().auth_policies.getTopicAuthentication()
                                    .get(resource.getName());
                            if (topicRoles != null && role != null) {
                                // Topic has custom policy
                                Set<AuthAction> topicActions = topicRoles.get(role);
                                if (topicActions != null && !topicActions.isEmpty()) {
                                    canLookupFuture.complete(true);
                                    return;
                                }
                            }
                        }
                        canLookupFuture.complete(false);
                    }).exceptionally(ex -> {
                        log.warn("Client with Principal - {} failed to get permissions for resource - {}. {}", principal, resource,
                                ex.getMessage());
                        canLookupFuture.completeExceptionally(ex);
                        return null;
                    });
        } catch (Exception e) {
            log.warn("Client with Principal - {} failed to get permissions for resource - {}. {}", principal, resource,
                    e.getMessage());
            canLookupFuture.completeExceptionally(e);
        }
        return canLookupFuture;
    }
}
