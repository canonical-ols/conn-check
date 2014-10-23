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

from txrequests import Session
from requests.packages import urllib3

from .check_impl import (
    add_check_prefix,
    make_check,
    sequential_check,
    )


CA_CERTS = []


def load_ssl_certs(path):
    cert_map = {}
    for filepath in glob.glob("{}/*.pem".format(os.path.abspath(path))):
        # There might be some dead symlinks in there, so let's make sure it's real.
        if os.path.exists(filepath):
            data = open(filepath).read()
            x509 = load_certificate(FILETYPE_PEM, data)
            # Now, de-duplicate in case the same cert has multiple names.
            cert_map[x509.digest('sha1')] = x509

    CA_CERTS.extend(cert_map.values())


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
def do_tcp_check(host, port, ssl=False, ssl_verify=True,
                 timeout=None):
    """Generic connection check function."""
    if not isIPAddress(host):
        try:
            ip = yield reactor.resolve(host, timeout=(1, timeout))
        except DNSLookupError:
            raise ValueError("dns resolution failed")
    else:
        ip = host
    creator = ClientCreator(reactor, TCPCheckProtocol)
    try:
        if ssl:
            context = VerifyingContextFactory(ssl_verify, CA_CERTS)
            yield creator.connectSSL(ip, port, context,
                                     timeout=timeout)
        else:
            yield creator.connectTCP(ip, port, timeout=timeout)
    except TimeoutError:
        if ip == host:
            raise ValueError("timed out")
        else:
            raise ValueError("timed out connecting to %s" % ip)


def make_tcp_check(host, port, timeout=None, **kwargs):
    """Return a check for TCP connectivity."""
    return make_check("tcp:{}:{}".format(host, port),
                      lambda: do_tcp_check(host, port, timeout=timeout),
                      info="%s:%s" % (host, port))


def make_ssl_check(host, port, verify=True, timeout=None, **kwargs):
    """Return a check for SSL setup."""
    return make_check("ssl:{}:{}".format(host, port),
                      lambda: do_tcp_check(host, port, ssl=True,
                          ssl_verify=verify, timeout=timeout),
                      info="%s:%s" % (host, port))


class UDPCheckProtocol(DatagramProtocol):

    def __init__(self, host, port, send, expect, deferred=None,
                 timeout=None):
        self.host = host
        self.port = port
        self.send = send
        self.expect = expect
        self.deferred = deferred
        self.timeout = timeout

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
        self.delayed = reactor.callLater(self.timeout,
                                         self._finish,
                                         False, TimeoutError())

    def datagramReceived(self, datagram, addr):
        if datagram == self.expect:
            self._finish(True, True)
        else:
            self._finish(False, ValueError("unexpected reply"))


@inlineCallbacks
def do_udp_check(host, port, send, expect, timeout=None):
    """Generic connection check function."""
    if not isIPAddress(host):
        try:
            ip = yield reactor.resolve(host, timeout=(1, timeout))
        except DNSLookupError:
            raise ValueError("dns resolution failed")
    else:
        ip = host
    deferred = Deferred()
    protocol = UDPCheckProtocol(ip, port, send, expect, deferred, timeout)
    reactor.listenUDP(0, protocol)
    try:
        yield deferred
    except TimeoutError:
        if ip == host:
            raise ValueError("timed out")
        else:
            raise ValueError("timed out waiting for %s" % ip)


def make_udp_check(host, port, send, expect, timeout=None,
                   **kwargs):
    """Return a check for UDP connectivity."""
    return make_check("udp:{}:{}".format(host, port),
            lambda: do_udp_check(host, port, send, expect, timeout),
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
    proxy_host = kwargs.get('proxy_host')
    proxy_port = kwargs.get('proxy_port', 8000)
    timeout = kwargs.get('timeout', None)

    if proxy_host:
        subchecks.append(make_tcp_check(proxy_host, proxy_port,
                                        timeout=timeout))
    else:
        subchecks.append(make_tcp_check(host, port, timeout=timeout))

    @inlineCallbacks
    def do_request():
        proxies = {}
        if proxy_host:
            proxies['http'] = proxies['https']= '{}:{}'.format(
                                                 proxy_host, proxy_port)

        headers = kwargs.get('headers')
        body = kwargs.get('body')
        disable_tls_verification = kwargs.get('disable_tls_verification',
                                              False)

        if disable_tls_verification:
            urllib3.disable_warnings()

        args = {
            'method': method,
            'url': url,
            'verify': not disable_tls_verification,
            'timeout': timeout,
        }
        if headers:
            args['headers'] = headers
        if body:
            args['data'] = body
        if proxies:
            args['proxies'] = proxies

        with Session() as session:
            request = session.request(**args)

            response = yield request
            if response.status_code != expected_code:
                raise RuntimeError(
                    "Unexpected response code: {}".format(
                                               response.status_code))

    subchecks.append(make_check('http:{}'.format(url), do_request,
                     info='{} {}'.format(method, url)))
    return sequential_check(subchecks)


def make_amqp_check(host, port, username, password, use_ssl=True, vhost="/",
                    timeout=None, **kwargs):
    """Return a check for AMQP connectivity."""
    from txamqp.protocol import AMQClient
    from txamqp.client import TwistedDelegate
    from txamqp.spec import load as load_spec

    subchecks = []
    subchecks.append(make_tcp_check(host, port, timeout=timeout))

    if use_ssl:
        subchecks.append(make_ssl_check(host, port, verify=False,
                                        timeout=timeout))

    @inlineCallbacks
    def do_auth():
        """Connect and authenticate."""
        delegate = TwistedDelegate()
        spec = load_spec(resource_stream('conn_check', 'amqp0-8.xml'))
        creator = ClientCreator(reactor, AMQClient,
                                delegate, vhost, spec)
        client = yield creator.connectTCP(host, port, timeout=timeout)
        yield client.authenticate(username, password)

    subchecks.append(make_check("amqp:{}:{}".format(host, port),
                                do_auth, info="user %s" % (username,),))
    return sequential_check(subchecks)


def make_postgres_check(host, port, username, password, database,
                        timeout=None, **kwargs):
    """Return a check for Postgres connectivity."""

    import psycopg2
    subchecks = []
    connect_kw = {
        'host': host,
        'user': username,
        'database': database,
        'connect_timeout': timeout,
    }

    if host[0] != '/':
        connect_kw['port'] = port
        subchecks.append(make_tcp_check(host, port, timeout=timeout))

    if password is not None:
        connect_kw['password'] = password

    def check_auth():
        """Try to establish a postgres connection and log in."""
        conn = psycopg2.connect(**connect_kw)
        conn.close()

    subchecks.append(make_check("postgres:{}:{}".format(host, port),
                                check_auth, info="user %s" % (username,),
                                blocking=True))
    return sequential_check(subchecks)


def make_redis_check(host, port, password=None, timeout=None,
                     **kwargs):
    """Make a check for the configured redis server."""
    import txredis
    subchecks = []
    subchecks.append(make_tcp_check(host, port, timeout=timeout))

    @inlineCallbacks
    def do_connect():
        """Connect and authenticate.
        """
        client_creator = ClientCreator(reactor, txredis.client.RedisClient)
        client = yield client_creator.connectTCP(host=host, port=port,
                                                 timeout=timeout)

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
    return add_check_prefix('redis:{}:{}'.format(host, port),
                            sequential_check(subchecks))


def make_memcache_check(host, port, password=None, timeout=None,
                        **kwargs):
    """Make a check for the configured redis server."""
    subchecks = []
    subchecks.append(make_tcp_check(host, port, timeout=timeout))

    @inlineCallbacks
    def do_connect():
        """Connect and authenticate.
        """
        client_creator = ClientCreator(reactor, MemCacheProtocol)
        client = yield client_creator.connectTCP(host=host, port=port,
                                                 timeout=timeout)

        version = yield client.version()

    subchecks.append(make_check('connect', do_connect))
    return add_check_prefix('memcache:{}:{}'.format(host, port),
                            sequential_check(subchecks))


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
