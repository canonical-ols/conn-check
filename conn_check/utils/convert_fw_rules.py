from argparse import ArgumentParser
from netaddr import IPNetwork
from socket import gethostbyname
import sys
import yaml


COMMANDS = {
    'aws': ('aws ec2 authorize-security-group-egress --group-id {group}'
            '--protocol {protocol} --port {port} --cidr {cidr}'),
    'neutron': ('neutron security-group-rule-create --direction egress'
                ' --ethertype {ip_version} --protocol {protocol} '
                ' --port-range-min {port} --port-range-max {port} '
                ' --remote-ip-prefix {cidr} {group}'),
    'nova': ('nova secgroup-add-rule {group} {protocol} {port} {port} {cidr}'),
    'iptables': ('iptables -A OUTPUT -p {protocol} --dport {port}'
                 ' -d {to_host} -j ACCEPT'),
    'ufw': ('ufw allow proto {protocol} from any to {cidr} port {port}'),
}

COMMAND_ALIASES = {
    'amazon': 'aws',
    'ec2': 'aws',
    'openstack': 'neutron',
    'os': 'neutron',
}


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


def output_secgroup_commands(cmd_type, rules, group='$SECGROUP'):
    """Generate firewall client commands from conn-check firewall rules."""
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

    return output


def run(*args):
    parser = ArgumentParser()
    parser.add_argument('-t', '--type', dest='output_type', required=True,
                        help="Rules output type, e.g. neutron, nova, aws,"
                        " iptables, ufw.")
    parser.add_argument("paths", nargs='+',
                        help="Paths to YAML files to combine/parse.")
    parser.add_argument('--group', dest='group', required=False,
                        help="AWS security group ID or OpenStack Neutron group"
                        " name.")
    options = parser.parse_args(list(args))

    rules = merge_yaml(options.paths)

    available_commands = COMMANDS.keys() + COMMAND_ALIASES.keys()
    output_type = options.output_type.lower()
    if output_type not in available_commands:
        sys.stderr.write('Error: invalid output type ({})\n'.format(
                         options.output_type))
        return 1

    command_type = COMMAND_ALIASES.get(output_type, output_type)
    output_rules = output_secgroup_commands(command_type, rules, options.group)

    sys.stdout.write('{}\n'.format('\n'.join(output_rules)))
    return 0


def main():
    sys.exit(run(*sys.argv[1:]))


if __name__ == '__main__':
    main()
