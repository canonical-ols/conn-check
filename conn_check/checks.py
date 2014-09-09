import glob
import os
from pkg_resources import resource_stream
import urlparse

from OpenSSL import SSL
from OpenSSL.crypto import load_certificate, FILETYPE_PEM

from twisted.internet import reactor, ssl
from twisted.internet.error import DNSLookupError, TimeoutError
from twisted.internet.abstract import isIPAddress
from twisted.internet.defer import (
    Deferred,
    inlineCallbacks,
    )
from twisted.internet.protocol import (
    ClientCreator,
    DatagramProtocol,
    Protocol,
    )
from twisted.protocols.memcache import MemCacheProtocol
from twisted.web.client import Agent

from .check_impl import (
    add_check_prefix,
    make_check,
    sequential_check,
    )


CONNECT_TIMEOUT = 10
CA_CERTS = []


for certFileName in glob.glob("/etc/ssl/certs/*.pem"):
    # There might be some dead symlinks in there, so let's make sure it's real.
    if os.path.exists(certFileName):
        data = open(certFileName).read()
        x509 = load_certificate(FILETYPE_PEM, data)
        # Now, de-duplicate in case the same cert has multiple names.
        CA_CERTS.append(x509)


class TCPCheckProtocol(Protocol):

    def connectionMade(self):
        self.transport.loseConnection()


class VerifyingContextFactory(ssl.CertificateOptions):

    def __init__(self, verify, caCerts, verifyCallback=None):
        ssl.CertificateOptions.__init__(self, verify=verify,
                                        caCerts=caCerts,
                                        method=SSL.SSLv23_METHOD)
        self.verifyCallback = verifyCallback

    def _makeContext(self):
        context = ssl.CertificateOptions._makeContext(self)
        if self.verifyCallback is not None:
            context.set_verify(
                SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT,
                self.verifyCallback)
        return context


@inlineCallbacks
def do_tcp_check(host, port, ssl=False, ssl_verify=True):
    """Generic connection check function."""
    if not isIPAddress(host):
        try:
            ip = yield reactor.resolve(host, timeout=(1, CONNECT_TIMEOUT))
        except DNSLookupError:
            raise ValueError("dns resolution failed")
    else:
        ip = host
    creator = ClientCreator(reactor, TCPCheckProtocol)
    try:
        if ssl:
            context = VerifyingContextFactory(ssl_verify, CA_CERTS)
            yield creator.connectSSL(ip, port, context,
                                     timeout=CONNECT_TIMEOUT)
        else:
            yield creator.connectTCP(ip, port, timeout=CONNECT_TIMEOUT)
    except TimeoutError:
        if ip == host:
            raise ValueError("timed out")
        else:
            raise ValueError("timed out connecting to %s" % ip)


def make_tcp_check(host, port, **kwargs):
    """Return a check for TCP connectivity."""
    return make_check("tcp:{}:{}".format(host, port), lambda: do_tcp_check(host, port),
                      info="%s:%s" % (host, port))


def make_ssl_check(host, port, verify=True, **kwargs):
    """Return a check for SSL setup."""
    return make_check("ssl:{}:{}".format(host, port),
                      lambda: do_tcp_check(host, port, ssl=True,
                          ssl_verify=verify),
                      info="%s:%s" % (host, port))


class UDPCheckProtocol(DatagramProtocol):

    def __init__(self, host, port, send, expect, deferred=None):
        self.host = host
        self.port = port
        self.send = send
        self.expect = expect
        self.deferred = deferred

    def _finish(self, success, result):
        if not (self.delayed.cancelled or self.delayed.called):
            self.delayed.cancel()
        if self.deferred is not None:
            if success:
                self.deferred.callback(result)
            else:
                self.deferred.errback(result)
            self.deferred = None

    def startProtocol(self):
        self.transport.write(self.send, (self.host, self.port))
        self.delayed = reactor.callLater(CONNECT_TIMEOUT,
                                         self._finish,
                                         False, TimeoutError())

    def datagramReceived(self, datagram, addr):
        if datagram == self.expect:
            self._finish(True, True)
        else:
            self._finish(False, ValueError("unexpected reply"))


@inlineCallbacks
def do_udp_check(host, port, send, expect):
    """Generic connection check function."""
    if not isIPAddress(host):
        try:
            ip = yield reactor.resolve(host, timeout=(1, CONNECT_TIMEOUT))
        except DNSLookupError:
            raise ValueError("dns resolution failed")
    else:
        ip = host
    deferred = Deferred()
    protocol = UDPCheckProtocol(host, port, send, expect, deferred)
    reactor.listenUDP(0, protocol)
    try:
        yield deferred
    except TimeoutError:
        if ip == host:
            raise ValueError("timed out")
        else:
            raise ValueError("timed out waiting for %s" % ip)


def make_udp_check(host, port, send, expect, **kwargs):
    """Return a check for UDP connectivity."""
    return make_check("udp:{}:{}".format(host, port),
            lambda: do_udp_check(host, port, send, expect),
                      info="%s:%s" % (host, port))


def extract_host_port(url):
    parsed = urlparse.urlparse(url)
    host = parsed.hostname
    port = parsed.port
    scheme = parsed.scheme
    if not scheme:
        scheme = 'http'
    if port is None:
        if scheme == 'https':
            port = 443
        else:
            port = 80
    return host, port, scheme


def make_http_check(url, method='GET', expected_code=200, **kwargs):
    subchecks = []
    host, port, scheme = extract_host_port(url)
    subchecks.append(make_tcp_check(host, port))
    if scheme == 'https':
        subchecks.append(make_ssl_check(host, port))

    @inlineCallbacks
    def do_request():
        agent = Agent(reactor)
        response = yield agent.request(method, url)
        if response.code != expected_code:
            raise RuntimeError(
                "Unexpected response code: {}".format(response.code))

    subchecks.append(make_check('http:{}'.format(url), do_request,
                     info='{} {}'.format(method, url)))
    return sequential_check(subchecks)


def make_amqp_check(host, port, username, password, use_ssl=True, vhost="/", **kwargs):
    """Return a check for AMQP connectivity."""
    from txamqp.protocol import AMQClient
    from txamqp.client import TwistedDelegate
    from txamqp.spec import load as load_spec

    subchecks = []
    subchecks.append(make_tcp_check(host, port))

    if use_ssl:
        subchecks.append(make_ssl_check(host, port, verify=False))

    @inlineCallbacks
    def do_auth():
        """Connect and authenticate."""
        delegate = TwistedDelegate()
        spec = load_spec(resource_stream('conn_check', 'amqp0-8.xml'))
        creator = ClientCreator(reactor, AMQClient,
                                delegate, vhost, spec)
        client = yield creator.connectTCP(host, port, timeout=CONNECT_TIMEOUT)
        yield client.authenticate(username, password)

    subchecks.append(make_check("auth", do_auth,
                                info="user %s" % (username,),))
    return sequential_check(subchecks)


def make_postgres_check(host, port, username, password, database, **kwargs):
    """Return a check for Postgres connectivity."""

    import psycopg2
    subchecks = []
    connect_kw = {'host': host, 'user': username, 'database': database}

    if host[0] != '/':
        connect_kw['port'] = port
        subchecks.append(make_tcp_check(host, port))

    if password is not None:
        connect_kw['password'] = password

    def check_auth():
        """Try to establish a postgres connection and log in."""
        conn = psycopg2.connect(**connect_kw)
        conn.close()

    subchecks.append(make_check("auth", check_auth,
                                info="user %s" % (username,),
                                blocking=True))
    return sequential_check(subchecks)


def make_redis_check(host, port, password=None, **kwargs):
    """Make a check for the configured redis server."""
    import txredis
    subchecks = []
    subchecks.append(make_tcp_check(host, port))

    @inlineCallbacks
    def do_connect():
        """Connect and authenticate.
        """
        client_creator = ClientCreator(reactor, txredis.client.RedisClient)
        client = yield client_creator.connectTCP(host=host, port=port,
                                                 timeout=CONNECT_TIMEOUT)

        if password is None:
            ping = yield client.ping()
            if not ping:
                raise RuntimeError("failed to ping redis")
        else:
            resp = yield client.auth(password)
            if resp != 'OK':
                raise RuntimeError("failed to auth to redis")

    connect_info = "connect with auth" if password is not None else "connect"
    subchecks.append(make_check(connect_info, do_connect))
    return add_check_prefix('redis', sequential_check(subchecks))


def make_memcache_check(host, port, password=None, **kwargs):
    """Make a check for the configured redis server."""
    subchecks = []
    subchecks.append(make_tcp_check(host, port))

    @inlineCallbacks
    def do_connect():
        """Connect and authenticate.
        """
        client_creator = ClientCreator(reactor, MemCacheProtocol)
        client = yield client_creator.connectTCP(host=host, port=port,
                                                 timeout=CONNECT_TIMEOUT)

        version = yield client.version()

    subchecks.append(make_check('connect', do_connect))
    return add_check_prefix('memcache', sequential_check(subchecks))


CHECKS = {
    'tcp': {
        'fn': make_tcp_check,
        'args': ['host', 'port'],
    },
    'ssl': {
        'fn': make_ssl_check,
        'args': ['host', 'port'],
    },
    'udp': {
        'fn': make_udp_check,
        'args': ['host', 'port', 'send', 'expect'],
    },
    'http': {
        'fn': make_http_check,
        'args': ['url'],
    },
    'amqp': {
        'fn': make_amqp_check,
        'args': ['host', 'port', 'username', 'password'],
    },
    'postgres': {
        'fn': make_postgres_check,
        'args': ['host', 'port', 'username', 'password', 'database'],
    },
    'redis': {
        'fn': make_redis_check,
        'args': ['host', 'port'],
    },
    'memcache': {
        'fn': make_memcache_check,
        'args': ['host', 'port'],
    },
    'memcached': {
        'fn': make_memcache_check,
        'args': ['host', 'port'],
    },
}
