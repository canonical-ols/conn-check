#!/usr/bin/env python

from twisted.internet import protocol, reactor
from twisted.internet.error import CannotListenError, ConnectError
from twisted.internet.interfaces import IReactorTCP, IReactorSSL

from twisted.protocols import tls
from twisted.python import log

from twisted.web import http

from zope.interface import implements


class ProxyConnectError(ConnectError):
    pass


class HTTPProxyConnector(object):
    """Helper to wrap reactor connection API (TCP, SSL) via a CONNECT proxy."""
    implements(IReactorTCP, IReactorSSL)

    def __init__(self, proxy_host, proxy_port,
                 reactor=reactor):
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.reactor = reactor

    def listenTCP(port, factory, backlog=50, interface=''):
        raise CannotListenError("Cannot BIND via HTTP proxies")

    def connectTCP(self, host, port, factory, timeout=30, bindAddress=None):
        f = HTTPProxiedClientFactory(factory, host, port)
        self.reactor.connectTCP(self.proxy_host,
                                self.proxy_port,
                                f, timeout, bindAddress)

    def listenSSL(self, port, factory, contextFactory, backlog=50, interface=''):
        raise CannotListenError("Cannot BIND via HTTP proxies")

    def connectSSL(self, host, port, factory, contextFactory, timeout=30,
                   bindAddress=None):
        tlsFactory = tls.TLSMemoryBIOFactory(contextFactory, True, factory)
        return self.connectTCP(host, port, tlsFactory, timeout, bindAddress)


class HTTPProxiedClientFactory(protocol.ClientFactory):
    """ClientFactory wrapper that triggers an HTTP proxy CONNECT on connect"""
    def __init__(self, delegate, dst_host, dst_port):
        self.delegate = delegate
        self.dst_host = dst_host
        self.dst_port = dst_port

    def startedConnecting(self, connector):
        return self.delegate.startedConnecting(connector)

    def buildProtocol(self, addr):
        p = HTTPConnectTunneler(self.dst_host, self.dst_port, addr)
        p.factory = self
        return p

    def clientConnectionFailed(self, connector, reason):
        return self.delegate.clientConnectionFailed(connector, reason)

    def clientConnectionLost(self, connector, reason):
        return self.delegate.clientConnectionLost(connector, reason)


class HTTPConnectTunneler(protocol.Protocol):
    """Protocol that wraps transport with CONNECT proxy handshake on connect

    `factory` MUST be assigned in order to use this Protocol, and the value
    *must* have a `delegate` attribute to trigger wrapped, post-connect,
    factory (creation) methods.
    """
    http = None
    otherConn = None
    noisy = True

    def __init__(self, host, port, orig_addr):
        self.host = host
        self.port = port
        self.orig_addr = orig_addr

    def connectionMade(self):
        self.http = HTTPConnectSetup(self.host, self.port)
        self.http.parent = self
        self.http.makeConnection(self.transport)

    def connectionLost(self, reason):
        if self.noisy:
            log.msg("HTTPConnectTunneler connectionLost", reason)

        if self.otherConn is not None:
            self.otherConn.connectionLost(reason)
        if self.http is not None:
            self.http.connectionLost(reason)

    def proxyConnected(self):
        # TODO: Bail if `self.factory` is unassigned or
        # does not have a `delegate`
        self.otherConn = self.factory.delegate.buildProtocol(self.orig_addr)
        self.otherConn.makeConnection(self.transport)

        # Get any pending data from the http buf and forward it to otherConn
        buf = self.http.clearLineBuffer()
        if buf:
            self.otherConn.dataReceived(buf)

    def dataReceived(self, data):
        if self.otherConn is not None:
            if self.noisy:
                log.msg("%d bytes for otherConn %s" %
                        (len(data), self.otherConn))
            return self.otherConn.dataReceived(data)
        elif self.http is not None:
            if self.noisy:
                log.msg("%d bytes for proxy %s" %
                        (len(data), self.otherConn))
            return self.http.dataReceived(data)
        else:
            raise Exception("No handler for received data... :(")


class HTTPConnectSetup(http.HTTPClient):
    """HTTPClient protocol to send a CONNECT message for proxies.

    `parent` MUST be assigned to an HTTPConnectTunneler instance, or have a
    `proxyConnected` method that will be invoked post-CONNECT (http request)
    """
    noisy = True

    def __init__(self, host, port):
        self.host = host
        self.port = port

    def connectionMade(self):
        self.sendCommand('CONNECT', '%s:%d' % (self.host, self.port))
        self.endHeaders()

    def handleStatus(self, version, status, message):
        if self.noisy:
            log.msg("Got Status :: %s %s %s" % (status, message, version))
        if str(status) != "200":
            raise ProxyConnectError("Unexpected status on CONNECT: %s" % status)

    def handleHeader(self, key, val):
        if self.noisy:
            log.msg("Got Header :: %s: %s" % (key, val))

    def handleEndHeaders(self):
        if self.noisy:
            log.msg("End Headers")
        # TODO: Make sure parent is assigned, and has a proxyConnected callback
        self.parent.proxyConnected()

    def handleResponse(self, body):
        if self.noisy:
            log.msg("Got Response :: %s" % (body))


if __name__ == '__main__':
    import sys
    import argparse

    log.startLogging(sys.stderr)

    ap = argparse.ArgumentParser()
    ap.add_argument('--proxy-host', default='localhost')
    ap.add_argument('--proxy-port', default=8080, type=int)
    ns = ap.parse_args()

    proxy = HTTPProxyConnector(proxy_host=ns.proxy_host,
                               proxy_port=ns.proxy_port)

    def cb(*args, **kwargs):
        log.msg("Got callback: args=%s, kwargs=%s" %
                (args, kwargs))

    import twisted.web.client
    agent = twisted.web.client.Agent(reactor=proxy)
    d = agent.request('GET', 'https://www.google.com/robots.txt')
    d.addCallback(cb)

    reactor.run()
