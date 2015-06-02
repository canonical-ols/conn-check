import sys
import socket
import yaml

from .main import Command, parse_version_arg


class FirewallRulesOutput(object):
    """Outputs a set of YAML firewall rules matching checks."""

    def __init__(self, output):
        self.output = output
        self.output_data = {}
        self.fqdn = socket.getfqdn()

    def notify_skip(self, name):
        self.write(name)

    def write(self, data):
        if not any(x in data for x in ('tcp', 'udp')):
            return

        # Here we take the list of colon separated values in reverse order, so
        # we're guaranteed to get the host/port/proto for the TCP/UDP check
        # without the specific prefix (e.g. memcache, http)
        port, host, protocol = data.split(':')[::-1][0:3]
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


class FirewallExportCommand(Command):
    """CLI command runner for conn-check-export-fw"""

    def wrap_output(self, output):
        """Override some options in order to just output fw rules without
        performing checks"""
        # We don't want to actually perform the checks
        self.options.dry_run = True
        self.options.buffer_output = False
        self.options.show_duration = False

        super(FirewallExportCommand, self).wrap_output(output)

        self.output = FirewallRulesOutput(self.output)
        self.results.output = self.output


def main(*args):
    if parse_version_arg():
        return 0

    cmd = FirewallExportCommand(args)
    return cmd.run()


def run():
    sys.exit(main(*sys.argv[1:]))


if __name__ == '__main__':
    run()
