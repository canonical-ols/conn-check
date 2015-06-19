import operator
import random
import testtools
from StringIO import StringIO

from testtools import matchers

from conn_check.check_impl import (
    FunctionCheck,
    MultiCheck,
    parallel_strategy,
    PrefixCheckWrapper,
    sequential_strategy,
    )
from conn_check.checks import (
    CHECKS,
    extract_host_port,
    make_amqp_check,
    make_http_check,
    make_memcache_check,
    make_mongodb_check,
    make_postgres_check,
    make_redis_check,
    make_smtp_check,
    make_tls_check,
    make_tcp_check,
    make_udp_check,
    )
from conn_check.main import (
    build_checks,
    check_from_description,
    OrderedOutput,
    )


class FunctionCheckMatcher(testtools.Matcher):

    def __init__(self, name, info, blocking=False):
        self.name = name
        self.info = info
        self.blocking = blocking

    def match(self, matchee):
        checks = []
        checks.append(matchers.IsInstance(FunctionCheck))
        checks.append(matchers.Annotate(
            "name doesn't match",
            matchers.AfterPreprocessing(operator.attrgetter('name'),
                matchers.Equals(self.name))))
        checks.append(matchers.Annotate(
            "info doesn't match",
            matchers.AfterPreprocessing(operator.attrgetter('info'),
                matchers.Equals(self.info))))
        checks.append(matchers.Annotate(
            "blocking doesn't match",
            matchers.AfterPreprocessing(operator.attrgetter('blocking'),
                matchers.Equals(self.blocking))))
        return matchers.MatchesAll(*checks).match(matchee)

    def __str__(self):
        return ("Is a FunctionCheck with <name={} info={} "
                "blocking={}>".format(self.name, self.info, self.blocking))


class MultiCheckMatcher(testtools.Matcher):

    def __init__(self, strategy, subchecks):
        self.strategy = strategy
        self.subchecks = subchecks

    def match(self, matchee):
        checks = []
        checks.append(matchers.IsInstance(MultiCheck))
        checks.append(matchers.AfterPreprocessing(operator.attrgetter('strategy'),
                        matchers.Is(self.strategy)))
        checks.append(matchers.AfterPreprocessing(operator.attrgetter('subchecks'),
                        matchers.MatchesListwise(self.subchecks)))
        return matchers.MatchesAll(*checks).match(matchee)

    def __str__(self):
        return ("Is a MultiCheck with <strategy={} subchecks={}>"
                "".format(self.strategy, self.subchecks))


class ExtractHostPortTests(testtools.TestCase):

    def test_basic(self):
        self.assertEqual(extract_host_port('http://localhost:80/'),
            ('localhost', 80, 'http'))

    def test_no_scheme(self):
        self.assertEqual(extract_host_port('//localhost/'),
            ('localhost', 80, 'http'))

    def test_no_port_http(self):
        self.assertEqual(extract_host_port('http://localhost/'),
            ('localhost', 80, 'http'))

    def test_no_port_https(self):
        self.assertEqual(extract_host_port('https://localhost/'),
            ('localhost', 443, 'https'))


class ConnCheckTest(testtools.TestCase):

    def test_make_tcp_check(self):
        result = make_tcp_check('localhost', 8080)
        self.assertThat(result, FunctionCheckMatcher('tcp:localhost:8080', 'localhost:8080'))

    def test_make_tls_check(self):
        result = make_tls_check('localhost', 8080, verify=True)
        self.assertThat(result, FunctionCheckMatcher('tls:localhost:8080', 'localhost:8080'))

    def test_make_udp_check(self):
        result = make_udp_check('localhost', 8080, 'foo', 'bar')
        self.assertThat(result, FunctionCheckMatcher('udp:localhost:8080', 'localhost:8080'))

    def test_make_http_check(self):
        result = make_http_check('http://localhost/')
        self.assertIsInstance(result, PrefixCheckWrapper)
        self.assertEqual(result.prefix, 'http:http://localhost/:')
        wrapped = result.wrapped
        self.assertIsInstance(wrapped, MultiCheck)
        self.assertIs(wrapped.strategy, sequential_strategy)
        self.assertEqual(len(wrapped.subchecks), 2)
        self.assertThat(wrapped.subchecks[0],
                FunctionCheckMatcher('tcp:localhost:80', 'localhost:80'))
        self.assertThat(wrapped.subchecks[1],
                FunctionCheckMatcher('', 'GET http://localhost/'))

    def test_make_http_check_https(self):
        result = make_http_check('https://localhost/')
        self.assertIsInstance(result, PrefixCheckWrapper)
        self.assertEqual(result.prefix, 'http:https://localhost/:')
        wrapped = result.wrapped
        self.assertIsInstance(wrapped, MultiCheck)
        self.assertIs(wrapped.strategy, sequential_strategy)
        self.assertEqual(len(wrapped.subchecks), 2)
        self.assertThat(wrapped.subchecks[0],
                FunctionCheckMatcher('tcp:localhost:443', 'localhost:443'))
        self.assertThat(wrapped.subchecks[1],
                FunctionCheckMatcher('', 'GET https://localhost/'))

    def test_make_amqp_check(self):
        result = make_amqp_check('localhost', 8080, 'foo',
                                 'bar', use_tls=True, vhost='/')
        self.assertIsInstance(result, MultiCheck)
        self.assertIs(result.strategy, sequential_strategy)
        self.assertEqual(len(result.subchecks), 3)
        self.assertThat(result.subchecks[0],
                FunctionCheckMatcher('tcp:localhost:8080', 'localhost:8080'))
        self.assertThat(result.subchecks[1],
                FunctionCheckMatcher('tls:localhost:8080', 'localhost:8080'))
        self.assertThat(result.subchecks[2],
                FunctionCheckMatcher('amqp:localhost:8080', 'user foo'))

    def test_make_amqp_check_no_tls(self):
        result = make_amqp_check('localhost', 8080, 'foo',
                                 'bar', use_tls=False, vhost='/')
        self.assertIsInstance(result, MultiCheck)
        self.assertIs(result.strategy, sequential_strategy)
        self.assertEqual(len(result.subchecks), 2)
        self.assertThat(result.subchecks[0],
                FunctionCheckMatcher('tcp:localhost:8080', 'localhost:8080'))
        self.assertThat(result.subchecks[1],
                FunctionCheckMatcher('amqp:localhost:8080', 'user foo'))

    def test_make_postgres_check(self):
        result = make_postgres_check('localhost', 8080,'foo',
                                     'bar', 'test')
        self.assertIsInstance(result, MultiCheck)
        self.assertIs(result.strategy, sequential_strategy)
        self.assertEqual(len(result.subchecks), 2)
        self.assertThat(result.subchecks[0],
                FunctionCheckMatcher('tcp:localhost:8080', 'localhost:8080'))
        self.assertThat(result.subchecks[1],
                FunctionCheckMatcher('postgres:localhost:8080', 'user foo', blocking=True))

    def test_make_postgres_check_local_socket(self):
        result = make_postgres_check('/local.sock', 8080,'foo',
                                     'bar', 'test')
        self.assertIsInstance(result, MultiCheck)
        self.assertIs(result.strategy, sequential_strategy)
        self.assertEqual(len(result.subchecks), 1)
        self.assertThat(result.subchecks[0],
                FunctionCheckMatcher('postgres:/local.sock:8080', 'user foo', blocking=True))

    def test_make_redis_check(self):
        result = make_redis_check('localhost', 8080)
        self.assertIsInstance(result, PrefixCheckWrapper)
        self.assertEqual(result.prefix, 'redis:localhost:8080:')
        wrapped = result.wrapped
        self.assertIsInstance(wrapped, MultiCheck)
        self.assertIs(wrapped.strategy, sequential_strategy)
        self.assertEqual(len(wrapped.subchecks), 2)
        self.assertThat(wrapped.subchecks[0],
                FunctionCheckMatcher('tcp:localhost:8080', 'localhost:8080'))
        self.assertThat(wrapped.subchecks[1], FunctionCheckMatcher('connect', None))

    def test_make_redis_check_with_password(self):
        result = make_redis_check('localhost', 8080, 'foobar')
        self.assertIsInstance(result, PrefixCheckWrapper)
        self.assertEqual(result.prefix, 'redis:localhost:8080:')
        wrapped = result.wrapped
        self.assertIsInstance(wrapped, MultiCheck)
        self.assertIs(wrapped.strategy, sequential_strategy)
        self.assertEqual(len(wrapped.subchecks), 2)
        self.assertThat(wrapped.subchecks[0],
                FunctionCheckMatcher('tcp:localhost:8080', 'localhost:8080'))
        self.assertThat(wrapped.subchecks[1],
                        FunctionCheckMatcher('connect with auth', None))

    def test_make_memcache_check(self):
        result = make_memcache_check('localhost', 8080)
        self.assertIsInstance(result, PrefixCheckWrapper)
        self.assertEqual(result.prefix, 'memcache:localhost:8080:')
        wrapped = result.wrapped
        self.assertIsInstance(wrapped, MultiCheck)
        self.assertIs(wrapped.strategy, sequential_strategy)
        self.assertEqual(len(wrapped.subchecks), 2)
        self.assertThat(wrapped.subchecks[0],
                FunctionCheckMatcher('tcp:localhost:8080', 'localhost:8080'))
        self.assertThat(wrapped.subchecks[1], FunctionCheckMatcher('connect', None))

    def test_make_mongodb_check(self):
        result = make_mongodb_check('localhost', 8080)
        self.assertIsInstance(result, PrefixCheckWrapper)
        self.assertEqual(result.prefix, 'mongodb:localhost:8080:')
        wrapped = result.wrapped
        self.assertIsInstance(wrapped, MultiCheck)
        self.assertIs(wrapped.strategy, sequential_strategy)
        self.assertEqual(len(wrapped.subchecks), 2)
        self.assertThat(wrapped.subchecks[0],
                FunctionCheckMatcher('tcp:localhost:8080', 'localhost:8080'))
        self.assertThat(wrapped.subchecks[1], FunctionCheckMatcher('connect', None))

    def test_make_mongodb_check_with_username(self):
        result = make_mongodb_check('localhost', 8080, 'foo')
        self.assertIsInstance(result, PrefixCheckWrapper)
        self.assertEqual(result.prefix, 'mongodb:localhost:8080:')
        wrapped = result.wrapped
        self.assertIsInstance(wrapped, MultiCheck)
        self.assertIs(wrapped.strategy, sequential_strategy)
        self.assertEqual(len(wrapped.subchecks), 2)
        self.assertThat(wrapped.subchecks[0],
                FunctionCheckMatcher('tcp:localhost:8080', 'localhost:8080'))
        self.assertThat(wrapped.subchecks[1],
                FunctionCheckMatcher('connect with auth', None))

    def test_make_smtp_check(self):
        result = make_smtp_check('localhost', 8080, 'foo', 'bar',
                                 'foo@example.com', 'bax@example.com',
                                 use_tls=True)
        self.assertIsInstance(result, MultiCheck)
        self.assertIs(result.strategy, sequential_strategy)
        self.assertEqual(len(result.subchecks), 3)
        self.assertThat(result.subchecks[0],
                FunctionCheckMatcher('tcp:localhost:8080', 'localhost:8080'))
        self.assertThat(result.subchecks[1],
                FunctionCheckMatcher('tls:localhost:8080', 'localhost:8080'))
        self.assertThat(result.subchecks[2],
                FunctionCheckMatcher('smtp:localhost:8080', 'user foo'))

    def test_make_smtp_check_no_tls(self):
        result = make_smtp_check('localhost', 8080, 'foo', 'bar',
                                 'foo@example.com', 'bax@example.com',
                                 use_tls=False)
        self.assertIsInstance(result, MultiCheck)
        self.assertIs(result.strategy, sequential_strategy)
        self.assertEqual(len(result.subchecks), 2)
        self.assertThat(result.subchecks[0],
                FunctionCheckMatcher('tcp:localhost:8080', 'localhost:8080'))
        self.assertThat(result.subchecks[1],
                FunctionCheckMatcher('smtp:localhost:8080', 'user foo'))

    def test_check_from_description_unknown_type(self):
        e = self.assertRaises(AssertionError,
                              check_from_description, {'type': 'foo'})
        self.assertEqual(
            str(e),
            "Unknown check type: foo, available checks: {}".format(CHECKS.keys()))

    def test_check_from_description_missing_arg(self):
        description = {'type': 'tcp'}
        e = self.assertRaises(AssertionError,
                check_from_description, description)
        self.assertEqual(
            str(e),
            "host missing from check: {}".format(description))

    def test_check_from_description_makes_check(self):
        description = {'type': 'tcp', 'host': 'localhost', 'port': '8080'}
        result = check_from_description(description)
        self.assertThat(result,
                FunctionCheckMatcher('tcp:localhost:8080', 'localhost:8080'))

    def test_build_checks(self):
        description = [{'type': 'tcp', 'host': 'localhost', 'port': '8080'}]
        result = build_checks(description, 10, [], [])
        self.assertThat(result,
                MultiCheckMatcher(strategy=parallel_strategy,
                    subchecks=[FunctionCheckMatcher('tcp:localhost:8080', 'localhost:8080')]))

    def test_build_checks_with_tags(self):
        descriptions = [
            {'type': 'tcp', 'host': 'localhost', 'port': '8080'},
            {'type': 'tcp', 'host': 'localhost2', 'port': '8080',
             'tags': ['foo']},
            {'type': 'tcp', 'host': 'localhost3', 'port': '8080',
             'tags': ['foo', 'bar']},
            {'type': 'tcp', 'host': 'localhost4', 'port': '8080',
             'tags': ['baz']},
            {'type': 'tcp', 'host': 'localhost5', 'port': '8080',
             'tags': ['bar']},
        ]
        result = build_checks(descriptions, 10, ['foo', 'bar'], [])
        expected_subchecks = [
            FunctionCheckMatcher('tcp:localhost2:8080', 'localhost2:8080'),
            FunctionCheckMatcher('tcp:localhost3:8080', 'localhost3:8080'),
            FunctionCheckMatcher('tcp:localhost5:8080', 'localhost5:8080'),
        ]
        self.assertThat(result,
                MultiCheckMatcher(strategy=parallel_strategy,
                    subchecks=expected_subchecks))

    def test_build_checks_with_excluded_tags(self):
        descriptions = [
            {'type': 'tcp', 'host': 'localhost', 'port': '8080'},
            {'type': 'tcp', 'host': 'localhost2', 'port': '8080',
             'tags': ['foo']},
            {'type': 'tcp', 'host': 'localhost3', 'port': '8080',
             'tags': ['foo', 'bar']},
            {'type': 'tcp', 'host': 'localhost4', 'port': '8080',
             'tags': ['baz']},
            {'type': 'tcp', 'host': 'localhost5', 'port': '8080',
             'tags': ['bar']},
        ]
        result = build_checks(descriptions, 10, [], ['bar', 'baz'])
        expected_subchecks = [
            FunctionCheckMatcher('tcp:localhost:8080', 'localhost:8080'),
            FunctionCheckMatcher('tcp:localhost2:8080', 'localhost2:8080'),
        ]
        self.assertThat(result,
                MultiCheckMatcher(strategy=parallel_strategy,
                    subchecks=expected_subchecks))

    def test_ordered_output(self):
        lines = [
            'SKIPPED: xyz3:localhost:666\n',
            'bar2:localhost:8080 FAILED: error\n',
            'SKIPPED: foo2:localhost:8080\n',
            'baz2:localhost:42 OK\n',
            'SKIPPED: bar2:localhost:8080\n',
            'xyz2:localhost:666 FAILED: error\n',
            'xyz1:localhost:666 OK\n',
            'foo1:localhost:8080 FAILED: error\n',
            'baz1:localhost:42 OK\n',
        ]
        expected = (
            'bar2:localhost:8080 FAILED: error\n'
            'foo1:localhost:8080 FAILED: error\n'
            'xyz2:localhost:666 FAILED: error\n'
            'baz1:localhost:42 OK\n'
            'baz2:localhost:42 OK\n'
            'xyz1:localhost:666 OK\n'
            'SKIPPED: bar2:localhost:8080\n'
            'SKIPPED: foo2:localhost:8080\n'
            'SKIPPED: xyz3:localhost:666\n'
        )

        output = OrderedOutput(StringIO())
        map(output.write, lines)
        output.flush()
        self.assertEqual(expected, output.output.getvalue())

        output = OrderedOutput(StringIO())
        random.shuffle(lines)
        map(output.write, lines)
        output.flush()
        self.assertEqual(expected, output.output.getvalue())
