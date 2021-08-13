package io.streamnative.pulsar.handlers.kop.security;


import java.net.InetAddress;

public class Session {

    private KafkaPrincipal principal;

    private InetAddress clientAddress;

    public Session(KafkaPrincipal principal, InetAddress clientAddress) {
        this.principal = principal;
        this.clientAddress = clientAddress;
    }

    public KafkaPrincipal getPrincipal() {
        return principal;
    }

    public void setPrincipal(KafkaPrincipal principal) {
        this.principal = principal;
    }

    public InetAddress getClientAddress() {
        return clientAddress;
    }

    public void setClientAddress(InetAddress clientAddress) {
        this.clientAddress = clientAddress;
    }
}
