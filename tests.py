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
        checks.append(matchers.AfterPreprocessing(operator.attrgetter('name'),
                        matchers.Equals(self.name)))
        checks.append(matchers.AfterPreprocessing(operator.attrgetter('info'),
                        matchers.Equals(self.info)))
        checks.append(matchers.AfterPreprocessing(operator.attrgetter('blocking'),
                        matchers.Equals(self.blocking)))
        return matchers.MatchesAll(*checks).match(matchee)

    def __str__(self):
        return ("Is a FunctionCheck with <name={} info={} "
                "blocking={}>".format(self.name, self.info, self.blocking))


class ConnCheckTest(testtools.TestCase):
    def test_make_tcp_check(self):
        result = conn_check.make_tcp_check('localhost', 8080)
        self.assertThat(result, FunctionCheckMatcher('tcp', 'localhost:8080'))

    def test_make_ssl_check(self):
        result = conn_check.make_ssl_check('localhost', 8080, True)
        self.assertThat(result, FunctionCheckMatcher('ssl', 'localhost:8080'))

    def test_make_udp_check(self):
        result = conn_check.make_udp_check('localhost', 8080, 'foo', 'bar')
        self.assertThat(result, FunctionCheckMatcher('udp', 'localhost:8080'))

    def test_make_amqp_check(self):
        result = conn_check.make_amqp_check('localhost', 8080, True, 'foo',
                                            'bar', '/')
        self.assertIsInstance(result, conn_check.MultiCheck)
        self.assertIs(result.strategy, conn_check.sequential_strategy)
        self.assertEqual(len(result.subchecks), 3)
        self.assertThat(result.subchecks[0], FunctionCheckMatcher('tcp', 'localhost:8080'))
        self.assertThat(result.subchecks[1], FunctionCheckMatcher('ssl', 'localhost:8080'))
        self.assertThat(result.subchecks[2], FunctionCheckMatcher('auth', 'user foo'))

    def test_make_amqp_check_no_ssl(self):
        result = conn_check.make_amqp_check('localhost', 8080, False, 'foo',
                                            'bar', '/')
        self.assertIsInstance(result, conn_check.MultiCheck)
        self.assertIs(result.strategy, conn_check.sequential_strategy)
        self.assertEqual(len(result.subchecks), 2)
        self.assertThat(result.subchecks[0], FunctionCheckMatcher('tcp', 'localhost:8080'))
        self.assertThat(result.subchecks[1], FunctionCheckMatcher('auth', 'user foo'))

    def test_make_postgres_check(self):
        result = conn_check.make_postgres_check('localhost', 8080,'foo',
                                                'bar', 'test')
        self.assertIsInstance(result, conn_check.MultiCheck)
        self.assertIs(result.strategy, conn_check.sequential_strategy)
        self.assertEqual(len(result.subchecks), 2)
        self.assertThat(result.subchecks[0], FunctionCheckMatcher('tcp', 'localhost:8080'))
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
