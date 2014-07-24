import operator
import testtools

from testtools import matchers

import conn_check


class FunctionCheckMatcher(testtools.Matcher):

    def __init__(self, name, info, blocking=False):
        self.name = name
        self.info = info
        self.blocking = blocking

    def match(self, matchee):
        checks = []
        checks.append(matchers.IsInstance(conn_check.FunctionCheck))
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
        checks.append(matchers.IsInstance(conn_check.MultiCheck))
        checks.append(matchers.AfterPreprocessing(operator.attrgetter('strategy'),
                        matchers.Is(self.strategy)))
        checks.append(matchers.AfterPreprocessing(operator.attrgetter('subchecks'),
                        matchers.MatchesListwise(self.subchecks)))
        return matchers.MatchesAll(*checks).match(matchee)

    def __str__(self):
        return ("Is a MultiCheck with <strategy={} subchecks={}>"
                "".format(self.strategy, self.subchecks))


class ConnCheckTest(testtools.TestCase):

    def test_make_tcp_check(self):
        result = conn_check.make_tcp_check('localhost', 8080)
        self.assertThat(result, FunctionCheckMatcher('tcp.localhost:8080', 'localhost:8080'))

    def test_make_ssl_check(self):
        result = conn_check.make_ssl_check('localhost', 8080, verify=True)
        self.assertThat(result, FunctionCheckMatcher('ssl.localhost:8080', 'localhost:8080'))

    def test_make_udp_check(self):
        result = conn_check.make_udp_check('localhost', 8080, 'foo', 'bar')
        self.assertThat(result, FunctionCheckMatcher('udp.localhost:8080', 'localhost:8080'))

    def test_make_amqp_check(self):
        result = conn_check.make_amqp_check('localhost', 8080, 'foo',
                                            'bar', use_ssl=True, vhost='/')
        self.assertIsInstance(result, conn_check.MultiCheck)
        self.assertIs(result.strategy, conn_check.sequential_strategy)
        self.assertEqual(len(result.subchecks), 3)
        self.assertThat(result.subchecks[0],
                FunctionCheckMatcher('tcp.localhost:8080', 'localhost:8080'))
        self.assertThat(result.subchecks[1],
                FunctionCheckMatcher('ssl.localhost:8080', 'localhost:8080'))
        self.assertThat(result.subchecks[2], FunctionCheckMatcher('auth', 'user foo'))

    def test_make_amqp_check_no_ssl(self):
        result = conn_check.make_amqp_check('localhost', 8080, 'foo',
                                            'bar', use_ssl=False, vhost='/')
        self.assertIsInstance(result, conn_check.MultiCheck)
        self.assertIs(result.strategy, conn_check.sequential_strategy)
        self.assertEqual(len(result.subchecks), 2)
        self.assertThat(result.subchecks[0],
                FunctionCheckMatcher('tcp.localhost:8080', 'localhost:8080'))
        self.assertThat(result.subchecks[1], FunctionCheckMatcher('auth', 'user foo'))

    def test_make_postgres_check(self):
        result = conn_check.make_postgres_check('localhost', 8080,'foo',
                                                'bar', 'test')
        self.assertIsInstance(result, conn_check.MultiCheck)
        self.assertIs(result.strategy, conn_check.sequential_strategy)
        self.assertEqual(len(result.subchecks), 2)
        self.assertThat(result.subchecks[0],
                FunctionCheckMatcher('tcp.localhost:8080', 'localhost:8080'))
        self.assertThat(result.subchecks[1],
                FunctionCheckMatcher('auth', 'user foo', blocking=True))

    def test_make_postgres_check_local_socket(self):
        result = conn_check.make_postgres_check('/local.sock', 8080,'foo',
                                                'bar', 'test')
        self.assertIsInstance(result, conn_check.MultiCheck)
        self.assertIs(result.strategy, conn_check.sequential_strategy)
        self.assertEqual(len(result.subchecks), 1)
        self.assertThat(result.subchecks[0],
                FunctionCheckMatcher('auth', 'user foo', blocking=True))

    def test_make_redis_check(self):
        result = conn_check.make_redis_check('localhost', 8080)
        self.assertIsInstance(result, conn_check.PrefixCheckWrapper)
        self.assertEqual(result.prefix, 'redis.')
        wrapped = result.wrapped
        self.assertIsInstance(wrapped, conn_check.MultiCheck)
        self.assertIs(wrapped.strategy, conn_check.sequential_strategy)
        self.assertEqual(len(wrapped.subchecks), 2)
        self.assertThat(wrapped.subchecks[0],
                FunctionCheckMatcher('tcp.localhost:8080', 'localhost:8080'))
        self.assertThat(wrapped.subchecks[1], FunctionCheckMatcher('connect', None))

    def test_make_redis_check_with_password(self):
        result = conn_check.make_redis_check('localhost', 8080, 'foobar')
        self.assertIsInstance(result, conn_check.PrefixCheckWrapper)
        self.assertEqual(result.prefix, 'redis.')
        wrapped = result.wrapped
        self.assertIsInstance(wrapped, conn_check.MultiCheck)
        self.assertIs(wrapped.strategy, conn_check.sequential_strategy)
        self.assertEqual(len(wrapped.subchecks), 2)
        self.assertThat(wrapped.subchecks[0],
                FunctionCheckMatcher('tcp.localhost:8080', 'localhost:8080'))
        self.assertThat(wrapped.subchecks[1],
                        FunctionCheckMatcher('connect and auth', None))

    def test_check_from_description_unknown_type(self):
        e = self.assertRaises(AssertionError,
                conn_check.check_from_description, {'type': 'foo'})
        self.assertEqual(
            str(e),
            "Unknown check type: foo, available checks: {}".format(conn_check.CHECKS.keys()))

    def test_check_from_description_missing_arg(self):
        description = {'type': 'tcp'}
        e = self.assertRaises(AssertionError,
                conn_check.check_from_description, description)
        self.assertEqual(
            str(e),
            "host missing from check: {}".format(description))

    def test_check_from_description_makes_check(self):
        description = {'type': 'tcp', 'host': 'localhost', 'port': '8080'}
        result = conn_check.check_from_description(description)
        self.assertThat(result,
                FunctionCheckMatcher('tcp.localhost:8080', 'localhost:8080'))

    def test_build_checks(self):
        description = [{'type': 'tcp', 'host': 'localhost', 'port': '8080'}]
        result = conn_check.build_checks(description)
        self.assertThat(result,
                MultiCheckMatcher(strategy=conn_check.parallel_strategy,
                    subchecks=[FunctionCheckMatcher('tcp.localhost:8080', 'localhost:8080')]))
