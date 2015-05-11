from argparse import ArgumentParser
from collections import defaultdict
import socket
import sys
from threading import Thread
import time
import traceback
import yaml

from twisted.internet import reactor
from twisted.internet.defer import (
    inlineCallbacks,
    )
from twisted.python.threadpool import ThreadPool

from . import get_version_string
from .check_impl import (
    FailureCountingResultWrapper,
    parallel_check,
    skipping_check,
    ResultTracker,
    )
from .checks import CHECK_ALIASES, CHECKS, load_tls_certs
from .patterns import (
    SimplePattern,
    SumPattern,
    )


def check_from_description(check_description, use_base_protocols=False):
    _type = check_description['type']

    if _type in CHECK_ALIASES:
        _type = CHECK_ALIASES[_type]

    check = CHECKS.get(_type, None)
    if check is None:
        raise AssertionError("Unknown check type: {}, available checks: {}"
                             .format(_type, CHECKS.keys()))
    for arg in check['args']:
        if arg not in check_description:
            raise AssertionError('{} missing from check: {}'.format(arg,
                                 check_description))

    # Flag to force check function to only perform a base TCP/UDP check
    if use_base_protocols:
        check_description['only_basic'] = True

    res = check['fn'](**check_description)
    return res


def filter_tags(check, include, exclude):
    if not include and not exclude:
        return True

    check_tags = set(check.get('tags', []))

    if include:
        result = bool(check_tags.intersection(include))
    else:
        result = not bool(check_tags.intersection(exclude))

    return result


def build_checks(check_descriptions, connect_timeout, include_tags,
                 exclude_tags, use_base_protocols=False, skip_checks=False):
    def set_timeout(desc):
        new_desc = dict(timeout=connect_timeout)
        new_desc.update(desc)
        return new_desc

    check_descriptions = filter(
        lambda c: filter_tags(c, include_tags, exclude_tags),
        check_descriptions)

    subchecks = map(
        lambda c: check_from_description(c, use_base_protocols),
        map(set_timeout, check_descriptions))

    if skip_checks:
        strategy_wrapper = skipping_check
    else:
        strategy_wrapper = parallel_check
    return strategy_wrapper(subchecks)


@inlineCallbacks
def run_checks(checks, pattern, results):
    """Make and run all the pertinent checks."""
    try:
        yield checks.check(pattern, results)
    finally:
        reactor.stop()


class NagiosCompatibleArgsParser(ArgumentParser):

    def error(self, message):
        """A patched version of ArgumentParser.error which does the same
        thing, e.g. prints an error message and exits, but does so with
        an exit code of 3 rather than 2, to maintain compatibility with
        Nagios checks."""
        self.print_usage(sys.stderr)
        self.exit(3, '%s: error: %s\n' % (self.prog, message))


class TimestampOutput(object):

    def __init__(self, output):
        self.start = time.time()
        self.output = output

    def write(self, data):
        self.output.write("%.3f: %s" % (time.time() - self.start, data))


class OrderedOutput(object):
    """Outputs check results ordered by FAILED, SUCCESSFUL, SKIPPED checks."""

    def __init__(self, output):
        self.output = output

        self.failed = defaultdict(list)
        self.messages = defaultdict(list)
        self.skipped = []

    def write(self, data):
        if data[:7] == 'SKIPPED':
            self.skipped.append(data)
            return

        name, message = data.split(' ', 1)

        # Standard check name format is {type}:{host}:{port}
        name_parts = name.split(':', 2)
        try:
            name_parts[2] = ''
        except IndexError:
            pass
        name = ':'.join(name_parts)

        if message[0:6] == 'FAILED':
            self.failed[name].append(data)
        else:
            self.messages[name].append(data)

    def flush(self):
        for _type in ('failed', 'messages'):
            for name, messages in sorted(getattr(self, _type).items()):
                messages.sort()
                map(self.output.write, messages)

        self.skipped.sort()
        map(self.output.write, self.skipped)


class FirewallRulesOutput(object):
    """Outputs a set of YAML firewall rules matching checks."""

    def __init__(self, output):
        self.output = output
        self.output_data = {}
        self.fqdn = socket.getfqdn()

    def write(self, data):
        parts = data.lstrip('SKIPPING: ')
        # Here we take the list of colon separated values in reverse order, so
        # we're guaranteed to get the host/port/proto for the TCP/UDP check
        # without the specific prefix (e.g. memcache, http)
        port, host, protocol = parts.split(':')[::-1][0:3]
        protocol = protocol.strip()

        key = "{}:{}".format(host, protocol)
        if key not in self.output_data:
            self.output_data[key] = {
                'from_host': self.fqdn,
                'to_host': host,
                'ports': [],
                'protocol': protocol,
            }

        port = int(port)
        if port not in self.output_data[key]['ports']:
            self.output_data[key]['ports'].append(port)

    def flush(self):
        self.output.write(yaml.dump({'egress': self.output_data.values()}))


class ConsoleOutput(ResultTracker):
    """Outputs check results to STDOUT."""

    def __init__(self, output, verbose, show_tracebacks, show_duration):
        """Initialize an instance."""
        super(ConsoleOutput, self).__init__()
        self.output = output
        self.verbose = verbose
        self.show_tracebacks = show_tracebacks
        self.show_duration = show_duration

    def format_duration(self, duration):
        if not self.show_duration:
            return ""
        return ": (%.3f ms)" % duration

    def notify_start(self, name, info):
        """Register the start of a check."""
        if self.verbose:
            if info:
                info = " (%s)" % (info,)
            else:
                info = ''
            self.output.write("Starting %s%s...\n" % (name, info))

    def notify_skip(self, name):
        """Register a check being skipped."""
        self.output.write("SKIPPED: %s\n" % (name,))

    def notify_success(self, name, duration):
        """Register a success."""
        self.output.write("%s OK%s\n" % (
            name, self.format_duration(duration)))

    def notify_failure(self, name, info, exc_info, duration):
        """Register a failure."""
        message = str(exc_info[1]).split("\n")[0]
        if info:
            message = "(%s) %s" % (info, message)
        self.output.write("%s FAILED%s - %s\n" % (
            name, self.format_duration(duration), message))

        if self.show_tracebacks:
            formatted = traceback.format_exception(exc_info[0],
                                                   exc_info[1],
                                                   exc_info[2],
                                                   None)
            lines = "".join(formatted).split("\n")
            if len(lines) > 0 and len(lines[-1]) == 0:
                lines.pop()
            indented = "\n".join(["  %s" % (line,) for line in lines])
            self.output.write("%s\n" % (indented,))


def main(*args):
    """Parse arguments, then build and run checks in a reactor."""

    # We do this first because ArgumentParser won't let us mix and match
    # non-default positional argument with a flag argument
    if '--version' in sys.argv:
        sys.stdout.write('conn-check {}\n'.format(get_version_string()))
        return 0

    parser = NagiosCompatibleArgsParser()
    parser.add_argument("config_file",
                        help="Config file specifying the checks to run.")
    parser.add_argument("patterns", nargs='*',
                        help="Patterns to filter the checks.")
    parser.add_argument("-v", "--verbose", dest="verbose",
                        action="store_true", default=False,
                        help="Show additional status")
    parser.add_argument("-d", "--duration", dest="show_duration",
                        action="store_true", default=False,
                        help="Show duration")
    parser.add_argument("-t", "--tracebacks", dest="show_tracebacks",
                        action="store_true", default=False,
                        help="Show tracebacks on failure")
    parser.add_argument("--validate", dest="validate",
                        action="store_true", default=False,
                        help="Only validate the config file, don't run checks."
                        )
    parser.add_argument("--version", dest="print_version",
                        action="store_true", default=False,
                        help="Print the currently installed version.")
    parser.add_argument("--tls-certs-path", dest="cacerts_path",
                        action="store", default="/etc/ssl/certs/",
                        help="Path to TLS CA certificates.")
    parser.add_argument("--max-timeout", dest="max_timeout", type=float,
                        action="store", help="Maximum execution time.")
    parser.add_argument("--connect-timeout", dest="connect_timeout",
                        action="store", default=10, type=float,
                        help="Network connection timeout.")
    parser.add_argument("-U", "--unbuffered-output", dest="buffer_output",
                        action="store_false", default=True,
                        help="Don't buffer output, write to STDOUT right "
                             "away.")
    parser.add_argument("-R", "--output-fw-rules", dest="output_fw_rules",
                        action="store_true", default=False,
                        help="Output proposed firewall rules in YAML,"
                        " implies -B/--use-base-protocols and"
                        " --dry-run.")
    parser.add_argument("-B", "--use-base-protocols",
                        dest="use_base_protocols", action="store_true",
                        default=False, help="Use only base TCP/UDP checks.")
    parser.add_argument("--dry-run",
                        dest="skip", action="store_true",
                        default=False, help="Skip all checks, just print out"
                        " what would be run.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--include-tags", dest="include_tags",
                       action="store", default="",
                       help="Comma separated list of tags to include.")
    group.add_argument("--exclude-tags", dest="exclude_tags",
                       action="store", default="",
                       help="Comma separated list of tags to exclude.")
    options = parser.parse_args(list(args))

    load_tls_certs(options.cacerts_path)

    if options.patterns:
        pattern = SumPattern(map(SimplePattern, options.patterns))
    else:
        pattern = SimplePattern("*")

    def make_daemon_thread(*args, **kw):
        """Create a daemon thread."""
        thread = Thread(*args, **kw)
        thread.daemon = True
        return thread

    threadpool = ThreadPool(minthreads=1)
    threadpool.threadFactory = make_daemon_thread
    reactor.threadpool = threadpool
    reactor.callWhenRunning(threadpool.start)

    output = sys.stdout

    if options.show_duration:
        output = TimestampOutput(output)

    if options.output_fw_rules:
        output = FirewallRulesOutput(output)

        # We only need TCP/UDP checks
        options.use_base_protocols = True
        # We don't want to actually perform the checks
        options.skip = True
    elif options.buffer_output:
        # We buffer output so we can order it for human readable output
        output = OrderedOutput(output)

    include = options.include_tags.split(',') if options.include_tags else []
    exclude = options.exclude_tags.split(',') if options.exclude_tags else []

    results = ConsoleOutput(output=output,
                            show_tracebacks=options.show_tracebacks,
                            show_duration=options.show_duration,
                            verbose=options.verbose)
    results = FailureCountingResultWrapper(results)
    with open(options.config_file) as f:
        descriptions = yaml.load(f)

    checks = build_checks(descriptions, options.connect_timeout,
                          include, exclude, options.use_base_protocols,
                          options.skip)

    if options.max_timeout is not None:
        def terminator():
            # Hasta la vista, twisted
            reactor.stop()
            print('Maximum timeout reached: {}s'.format(options.max_timeout))

        reactor.callLater(options.max_timeout, terminator)

    if not options.validate:
        reactor.callWhenRunning(run_checks, checks, pattern, results)

        reactor.run()

        # Flush output, this really only has an effect when running buffered
        # output
        output.flush()

        if results.any_failed():
            return 2
        else:
            return 0


def run():
    exit(main(*sys.argv[1:]))


if __name__ == '__main__':
    run()
