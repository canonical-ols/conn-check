import re


class Pattern(object):
    """Abstract base class for patterns used to select subsets of checks."""

    def assume_prefix(self, prefix):
        """Return an equivalent pattern with the given prefix baked in.

        For example, if self.matches("bar") is True, then
        self.assume_prefix("foo").matches("foobar") will be True.
        """
        return PrefixPattern(prefix, self)

    def failed(self):
        """Return True if the pattern cannot match any string.

        This is mainly used so we can bail out early when recursing into
        check trees.
        """
        return not self.prefix_matches("")

    def prefix_matches(self, partial_name):
        """Return True if the partial name (a prefix) is a potential match."""
        raise NotImplementedError("{}.prefix_matches not "
                                  "implemented".format(type(self)))

    def matches(self, name):
        """Return True if the given name matches."""
        raise NotImplementedError("{}.match not "
                                  "implemented".format(type(self)))


class FailedPattern(Pattern):
    """Patterns that always fail to match."""

    def assume_prefix(self, prefix):
        """Return an equivalent pattern with the given prefix baked in."""
        return FAILED_PATTERN

    def prefix_matches(self, partial_name):
        """Return True if the partial name matches."""
        return False

    def matches(self, name):
        """Return True if the complete name matches."""
        return False


FAILED_PATTERN = FailedPattern()


PATTERN_TOKEN_RE = re.compile(r'\*|[^*]+')


def tokens_to_partial_re(tokens):
    """Convert tokens to a regular expression for matching prefixes."""

    def token_to_re(token):
        """Convert tokens to (begin, end, alt_end) triples."""
        if token == '*':
            return (r'(?:.*', ')?', ')')
        else:
            chars = list(token)
            begin = "".join(["(?:" + re.escape(c) for c in chars])
            end = "".join([")?" for c in chars])
            return (begin, end, end)

    subexprs = map(token_to_re, tokens)
    if len(subexprs) > 0:
        # subexpressions like (.*)? aren't accepted, so we may have to use
        # an alternate closing form for the last (innermost) subexpression
        (begin, _, alt_end) = subexprs[-1]
        subexprs[-1] = (begin, alt_end, alt_end)
    return re.compile("".join([se[0] for se in subexprs] +
                              [se[1] for se in reversed(subexprs)] +
                              [r'\Z']))


def tokens_to_re(tokens):
    """Convert tokens to a regular expression for exact matching."""

    def token_to_re(token):
        """Convert tokens to simple regular expressions."""
        if token == '*':
            return r'.*'
        else:
            return re.escape(token)

    return re.compile("".join(map(token_to_re, tokens) + [r'\Z']))


class SimplePattern(Pattern):
    """Pattern that matches according to the given pattern expression."""

    def __init__(self, pattern):
        """Initialize an instance."""
        super(SimplePattern, self).__init__()
        tokens = PATTERN_TOKEN_RE.findall(pattern)
        self.partial_re = tokens_to_partial_re(tokens)
        self.full_re = tokens_to_re(tokens)

    def prefix_matches(self, partial_name):
        """Return True if the partial name matches."""
        return self.partial_re.match(partial_name) is not None

    def matches(self, name):
        """Return True if the complete name matches."""
        return self.full_re.match(name) is not None


class PrefixPattern(Pattern):
    """Pattern that assumes a previously given prefix."""

    def __init__(self, prefix, pattern):
        """Initialize an instance."""
        super(PrefixPattern, self).__init__()
        self.prefix = prefix
        self.pattern = pattern

    def assume_prefix(self, prefix):
        """Return an equivalent pattern with the given prefix baked in."""
        return PrefixPattern(self.prefix + prefix, self.pattern)

    def prefix_matches(self, partial_name):
        """Return True if the partial name matches."""
        return self.pattern.prefix_matches(self.prefix + partial_name)

    def matches(self, name):
        """Return True if the complete name matches."""
        return self.pattern.matches(self.prefix + name)


class SumPattern(Pattern):
    """Pattern that matches if at least one given pattern matches."""

    def __init__(self, patterns):
        """Initialize an instance."""
        super(SumPattern, self).__init__()
        self.patterns = patterns

    def prefix_matches(self, partial_name):
        """Return True if the partial name matches."""
        for pattern in self.patterns:
            if pattern.prefix_matches(partial_name):
                return True
        return False

    def matches(self, name):
        """Return True if the complete name matches."""
        for pattern in self.patterns:
            if pattern.matches(name):
                return True
        return False
