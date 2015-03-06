from argparse import ArgumentParser
from collections import defaultdict, OrderedDict
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
    ResultTracker,
    )
from .checks import CHECK_ALIASES, CHECKS, load_tls_certs
from .patterns import (
    SimplePattern,
    SumPattern,
    )


def check_from_description(check_description):
    _type = check_description['type']

    if _type in CHECK_ALIASES:
        _type = CHECK_ALIASES[_type]

    check = CHECKS.get(_type, None)
    if check is None:
        raise AssertionError("Unknown check type: {}, available checks: {}".format(
            _type, CHECKS.keys()))
    for arg in check['args']:
        if arg not in check_description:
            raise AssertionError('{} missing from check: {}'.format(arg,
                check_description))
    res = check['fn'](**check_description)
    return res

def filter_tags(check, tags, exclude):
    if not tags and not exclude:
        return True

    check_tags = set(check.get('tags', []))

    if tags:
        result = bool(check_tags.intersection(tags))
    else:
        result = not bool(check_tags.intersection(exclude))

    return result


def build_checks(check_descriptions, connect_timeout, tags, exclude_tags):
    def set_timeout(desc):
        new_desc = dict(timeout=connect_timeout)
        new_desc.update(desc)
        return new_desc
    check_descriptions = filter(lambda c: filter_tags(c, tags, exclude_tags),
                                check_descriptions)
    subchecks = map(check_from_description,
        map(set_timeout, check_descriptions))
    return parallel_check(subchecks)


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


class ConsoleOutput(ResultTracker):
    """Displays check results."""

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
                        help="Only validate the config file, don't run checks.")
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

    if options.buffer_output:
        # We buffer output so we can order it for human readable output
        output = OrderedOutput(output)

    tags = options.include_tags.split(',') if options.include_tags else []
    exclude = options.exclude_tags.split(',') if options.exclude_tags  else []

    results = ConsoleOutput(output=output,
                            show_tracebacks=options.show_tracebacks,
                            show_duration=options.show_duration,
                            verbose=options.verbose)
    results = FailureCountingResultWrapper(results)
    with open(options.config_file) as f:
        descriptions = yaml.load(f)

    checks = build_checks(descriptions, options.connect_timeout, tags, exclude)

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

