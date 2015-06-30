from argparse import ArgumentParser
from netaddr import IPNetwork
from socket import gethostbyname
import sys
import yaml


def merge_yaml(paths):
    """Merge multiple firewall YAML rule files with hosts/ports de-duped."""
    merged_rules = {}

    for path in paths:
        rules = yaml.load(open(path))

        for rule in rules.get('egress', []):
            key = '{protocol}:{from_host}:{to_host}'.format(**rule)

            if key not in merged_rules:
                merged_rules[key] = rule
            else:
                ports = merged_rules[key]['ports']
                ports_diff = set(ports).difference(rule['ports'])

                if ports_diff:
                    merged_rules[key]['ports'] = ports + ports_diff

    return merged_rules.values()


COMMANDS = {
    'aws': ('aws ec2 authorize-security-group-egress --group-id {group}'
            '--protocol {protocol} --port {port} --cidr {cidr}'),
    'neutron': ('neutron security-group-rule-create --direction egress'
                ' --ethertype {ip_version} --protocol {protocol} '
                ' --port-range-min {port} --port-range-max {port} '
                ' --remote-ip-prefix {cidr} {group}'),
    'nova': ('nova secgroup-add-rule {group} {protocol} {port} {port} {cidr}'),
    'iptables': '',
}

COMMAND_TYPES = {
    'aws': 'aws',
    'amazon': 'aws',
    'ec2': 'aws',
    'neutron': 'neutron',
    'openstack': 'neutron',
    'os': 'neutron',
    'nova': 'nova',
    'iptables': 'iptables',
}


def output_secgroup_commands(cmd_type, rules, group='$SECGROUP'):
    output = []
    for rule in rules:
        for port in rule['ports']:
            ip = IPNetwork(gethostbyname(rule['to_host']))
            params = {
                'group': group,
                'cidr': str(ip.cidr),
                'port': port,
                'ip_version': 'IPv{}'.format(ip.version),
            }
            params.update(rule)
            output.append(COMMANDS[cmd_type].format(**params))

    return '\n'.join(output)


def run(*args):
    parser = ArgumentParser()
    parser.add_argument('-t', '--type', dest='output_type', required=True,
                        help="Rules output type, e.g. neutron, nova, aws,"
                        " iptables.")
    parser.add_argument("paths", nargs='+',
                        help="Paths to YAML files to combine/parse.")
    parser.add_argument('--group', dest='group', required=False,
                        help="AWS security group ID or OpenStack Neutron group"
                        " name.")
    parser.add_argument('--use-nova', dest='use_nova', default=False,
                        action="store_true",
                        help="Output novaclient commands for OpenStack rules.")
    options = parser.parse_args(list(args))

    rules = merge_yaml(options.paths)

    output_type = options.output_type.lower()
    if output_type not in COMMAND_TYPES:
        sys.stderr.write('Error: invalid output type ({})\n'.format(
                         options.output_type))
        return 1

    cmd_type = COMMAND_TYPES.get(output_type)
    output_rules = output_secgroup_commands(cmd_type, rules, options.group)

    sys.stdout.write('{}\n'.format(output_rules))
    return 0


def main():
    sys.exit(run(*sys.argv[1:]))


if __name__ == '__main__':
    main()
