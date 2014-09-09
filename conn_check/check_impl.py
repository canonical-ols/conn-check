import sys
import time

from twisted.internet import reactor
from twisted.internet.defer import (
    returnValue,
    inlineCallbacks,
    maybeDeferred,
    DeferredList,
    Deferred)
from twisted.python.failure import Failure


def maybeDeferToThread(f, *args, **kwargs):
    """
    Call the function C{f} using a thread from the given threadpool and return
    the result as a Deferred.

    @param f: The function to call. May return a deferred.
    @param *args: positional arguments to pass to f.
    @param **kwargs: keyword arguments to pass to f.

    @return: A Deferred which fires a callback with the result of f, or an
        errback with a L{twisted.python.failure.Failure} if f throws an
        exception.
    """
    threadpool = reactor.getThreadPool()

    d = Deferred()

    def realOnResult(result):
        if not isinstance(result, Failure):
            reactor.callFromThread(d.callback, result)
        else:
            reactor.callFromThread(d.errback, result)

    def onResult(success, result):
        assert success
        assert isinstance(result, Deferred)
        result.addBoth(realOnResult)

    threadpool.callInThreadWithCallback(onResult, maybeDeferred,
                                        f, *args, **kwargs)

    return d


class Check(object):
    """Abstract base class for objects embodying connectivity checks."""

    def check(self, pattern, results):
        """Run this check, if it matches the pattern.

        If the pattern matches, and this is a leaf node in the check tree,
        implementations of Check.check should call
        results.notify_start, then either results.notify_success or
        results.notify_failure.
        """
        raise NotImplementedError("%r.check not implemented" % type(self))

    def skip(self, pattern, results):
        """Indicate that this check has been skipped.

        If the pattern matches and this is a leaf node in the check tree,
        implementations of Check.skip should call results.notify_skip.
        """
        raise NotImplementedError("%r.skip not implemented" % type(self))


class ConditionalCheck(Check):
    """A Check that skips unless the given predicate is true at check time."""

    def __init__(self, wrapped, predicate):
        """Initialize an instance."""
        super(ConditionalCheck, self).__init__()
        self.wrapped = wrapped
        self.predicate = predicate

    def check(self, pattern, result):
        """Skip the check."""
        if self.predicate():
            return self.wrapped.check(pattern, result)
        else:
            self.skip(pattern, result)

    def skip(self, pattern, result):
        """Skip the check."""
        self.wrapped.skip(pattern, result)


class ResultTracker(object):
    """Base class for objects which report or record check results."""

    def notify_start(self, name, info):
        """Register the start of a check."""

    def notify_skip(self, name):
        """Register a check being skipped."""

    def notify_success(self, name, duration):
        """Register a successful check."""

    def notify_failure(self, name, info, exc_info, duration):
        """Register the failure of a check."""


class PrefixResultWrapper(ResultTracker):
    """ResultWrapper wrapper which adds a prefix to recorded results."""

    def __init__(self, wrapped, prefix):
        """Initialize an instance."""
        super(PrefixResultWrapper, self).__init__()
        self.wrapped = wrapped
        self.prefix = prefix

    def make_name(self, name):
        """Make a name by prepending the prefix."""
        return "%s%s" % (self.prefix, name)

    def notify_skip(self, name):
        """Register a check being skipped."""
        self.wrapped.notify_skip(self.make_name(name))

    def notify_start(self, name, info):
        """Register the start of a check."""
        self.wrapped.notify_start(self.make_name(name), info)

    def notify_success(self, name, duration):
        """Register success."""
        self.wrapped.notify_success(self.make_name(name), duration)

    def notify_failure(self, name, info, exc_info, duration):
        """Register failure."""
        self.wrapped.notify_failure(self.make_name(name),
                                      info, exc_info, duration)


class FailureCountingResultWrapper(ResultTracker):
    """ResultWrapper wrapper which counts failures."""

    def __init__(self, wrapped):
        """Initialize an instance."""
        super(FailureCountingResultWrapper, self).__init__()
        self.wrapped = wrapped
        self.failure_count = 0

    def notify_skip(self, name):
        """Register a check being skipped."""
        self.wrapped.notify_skip(name)

    def notify_start(self, name, info):
        """Register the start of a check."""
        self.failure_count += 1
        self.wrapped.notify_start(name, info)

    def notify_success(self, name, duration):
        """Register success."""
        self.failure_count -= 1
        self.wrapped.notify_success(name, duration)

    def notify_failure(self, name, info, exc_info, duration):
        """Register failure."""
        self.wrapped.notify_failure(name, info, exc_info, duration)

    def any_failed(self):
        """Return True if any checks using this wrapper failed so far."""
        return self.failure_count > 0


class FunctionCheck(Check):
    """A Check which takes a check function."""

    def __init__(self, name, check, info=None, blocking=False):
        """Initialize an instance."""
        super(FunctionCheck, self).__init__()
        self.name = name
        self.info = info
        self.check_fn = check
        self.blocking = blocking

    @inlineCallbacks
    def check(self, pattern, results):
        """Call the check function."""
        if not pattern.matches(self.name):
            returnValue(None)
        results.notify_start(self.name, self.info)
        start = time.time()
        try:
            if self.blocking:
                result = yield maybeDeferToThread(self.check_fn)
            else:
                result = yield maybeDeferred(self.check_fn)
            results.notify_success(self.name, time.time() - start)
            returnValue(result)
        except Exception:
            results.notify_failure(self.name, self.info,
                                   sys.exc_info(), time.time() - start)

    def skip(self, pattern, results):
        """Record the skip."""
        if not pattern.matches(self.name):
            return
        results.notify_skip(self.name)


class MultiCheck(Check):
    """A composite check comprised of multiple subchecks."""

    def __init__(self, subchecks, strategy):
        """Initialize an instance."""
        super(MultiCheck, self).__init__()
        self.subchecks = list(subchecks)
        self.strategy = strategy

    def check(self, pattern, results):
        """Run subchecks using the strategy supplied at creation time."""
        return self.strategy(self.subchecks, pattern, results)

    def skip(self, pattern, results):
        """Skip subchecks."""
        for subcheck in self.subchecks:
            subcheck.skip(pattern, results)


class PrefixCheckWrapper(Check):
    """Runs a given check, adding a prefix to its name.

    This works by wrapping the pattern and result tracker objects
    passed to .check and .skip.
    """

    def __init__(self, wrapped, prefix):
        """Initialize an instance."""
        super(PrefixCheckWrapper, self).__init__()
        self.wrapped = wrapped
        self.prefix = prefix

    def do_subcheck(self, subcheck, pattern, results):
        """Do a subcheck if the pattern could still match."""
        pattern = pattern.assume_prefix(self.prefix)
        if not pattern.failed():
            results = PrefixResultWrapper(wrapped=results,
                                          prefix=self.prefix)
            return subcheck(pattern, results)

    def check(self, pattern, results):
        """Run the check, prefixing results."""
        return self.do_subcheck(self.wrapped.check, pattern, results)

    def skip(self, pattern, results):
        """Skip checks, prefixing results."""
        self.do_subcheck(self.wrapped.skip, pattern, results)


@inlineCallbacks
def sequential_strategy(subchecks, pattern, results):
    """Run subchecks sequentially, skipping checks after the first failure.

    This is most useful when the failure of one check in the sequence
    would imply the failure of later checks -- for example, it probably
    doesn't make sense to run an SSL check if the basic TCP check failed.

    Use sequential_check to create a meta-check using this strategy.
    """
    local_results = FailureCountingResultWrapper(wrapped=results)
    failed = False
    for subcheck in subchecks:
        if failed:
            subcheck.skip(pattern, local_results)
        else:
            yield maybeDeferred(subcheck.check, pattern, local_results)
            if local_results.any_failed():
                failed = True


def parallel_strategy(subchecks, pattern, results):
    """A strategy which runs the given subchecks in parallel.

    Most checks can potentially block for long periods, and shouldn't have
    interdependencies, so it makes sense to run them in parallel to
    shorten the overall run time.

    Use parallel_check to create a meta-check using this strategy.
    """
    deferreds = [maybeDeferred(subcheck.check, pattern, results)
                 for subcheck in subchecks]
    return DeferredList(deferreds)


def parallel_check(subchecks):
    """Return a check that runs the given subchecks in parallel."""
    return MultiCheck(subchecks=subchecks, strategy=parallel_strategy)


def sequential_check(subchecks):
    """Return a check that runs the given subchecks in sequence."""
    return MultiCheck(subchecks=subchecks, strategy=sequential_strategy)


def add_check_prefix(*args):
    """Return an equivalent check with the given prefix prepended to its name.

    The final argument should be a check; the remaining arguments are treated
    as name components and joined with the check name using periods as
    separators.  For example, if the name of a check is "baz", then:

        add_check_prefix("foo", "bar", check)

    ...will return a check with the effective name "foo.bar.baz".
    """
    args = list(args)
    check = args.pop(-1)
    path = ".".join(args)
    return PrefixCheckWrapper(wrapped=check, prefix="%s:" % (path,))


def make_check(name, check, info=None, blocking=False):
    """Make a check object from a function."""
    return FunctionCheck(name=name, check=check, info=info, blocking=blocking)


def guard_check(check, predicate):
    """Wrap a check so that it is skipped unless the predicate is true."""
    return ConditionalCheck(wrapped=check, predicate=predicate)

