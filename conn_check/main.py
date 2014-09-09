from argparse import ArgumentParser
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

from .check_impl import (
    FailureCountingResultWrapper,
    parallel_check,
    ResultTracker,
    )
from .checks import CHECKS
from .patterns import (
    SimplePattern,
    SumPattern,
    )


def check_from_description(check_description):
    _type = check_description['type']
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


def build_checks(check_descriptions):
    subchecks = map(check_from_description, check_descriptions)
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
        self.output.write("SKIPPING: %s\n" % (name,))

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
    options = parser.parse_args(list(args))

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

    results = ConsoleOutput(output=output,
                            show_tracebacks=options.show_tracebacks,
                            show_duration=options.show_duration,
                            verbose=options.verbose)
    results = FailureCountingResultWrapper(results)
    with open(options.config_file) as f:
        descriptions = yaml.load(f)

    checks = build_checks(descriptions)
    if not options.validate:
        reactor.callWhenRunning(run_checks, checks, pattern, results)

        reactor.run()

        if results.any_failed():
            return 2
        else:
            return 0


def run():
    exit(main(*sys.argv[1:]))


if __name__ == '__main__':
    run()

