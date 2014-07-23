import unittest
import conn_check


class ConnCheckTest(unittest.TestCase):
    def test_make_tcp_check(self):
        result = conn_check.make_tcp_check('localhost', 8080)
        self.assertIsInstance(result, conn_check.FunctionCheck)
        self.assertEqual(result.name, 'tcp')
        self.assertEqual(result.info, 'localhost:8080')

    def test_make_udp_check(self):
        result = conn_check.make_udp_check('localhost', 8080, 'foo', 'bar')
        self.assertIsInstance(result, conn_check.FunctionCheck)
        self.assertEqual(result.name, 'udp')
        self.assertEqual(result.info, 'localhost:8080')
