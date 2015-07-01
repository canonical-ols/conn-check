from argparse import ArgumentParser
from netaddr import IPNetwork
from socket import gethostbyname
import sys
import yaml


COMMANDS = {
    'aws': ('aws ec2 authorize-security-group-egress --group-id {group}'
            ' --protocol {protocol} --port {port} --cidr {to_cidr}'),
    'neutron': ('neutron security-group-rule-create --direction egress'
                ' --ethertype {ip_version} --protocol {protocol} '
                ' --port-range-min {port} --port-range-max {port} '
                ' --remote-ip-prefix {to_cidr} {group}'),
    'nova': ('nova secgroup-add-rule {group} {protocol} {port} {port}'
             ' {to_cidr}'),
    'iptables': ('iptables -A FORWARD -p {protocol} --dport {port}'
                 ' -s {from_host} -d {to_host} -j ACCEPT'),
    'ufw': ('ufw allow proto {protocol} from any to {to_cidr} port {port}'),
}

COMMAND_ALIASES = {
    'amazon': 'aws',
    'ec2': 'aws',
    'openstack': 'neutron',
    'os': 'neutron',
}

SECGROUP_COMMANDS = ('aws', 'neutron', 'nova')


def merge_yaml(paths, use_from=False):
    """Merge multiple firewall YAML rule files with hosts/ports de-duped."""
    merged_rules = {}

    for path in paths:
        rules = yaml.load(open(path))

        for rule in rules.get('egress', []):
            from_ip = IPNetwork(gethostbyname(rule['from_host']))
            to_ip = IPNetwork(gethostbyname(rule['to_host']))

            # We need these values for de-duping, so we may as well add them
            # into the rule here to use later when generating commands.
            rule['to_cidr'] = str(to_ip.cidr)
            rule['ip_version'] = to_ip.version

            if use_from:
                rule['from_cidr'] = str(from_ip.cidr)
                key_template = '{protocol}:{from_cidr}:{to_cidr}'
            else:
                key_template = '{protocol}:{to_cidr}'
            key = key_template.format(**rule)

            if key not in merged_rules:
                merged_rules[key] = rule
            else:
                ports = merged_rules[key]['ports']
                ports_diff = set(ports).difference(rule['ports'])

                if ports_diff:
                    merged_rules[key]['ports'] = ports + ports_diff

    return merged_rules.values()


def generate_commands(cmd, rules, group=None):
    """Generate firewall client commands from conn-check firewall rules."""
    output = []
    for rule in rules:
        for port in rule['ports']:
            params = {
                'group': group or '$SECGROUP',
                'port': port,
            }
            params.update(rule)
            output.append(COMMANDS[cmd].format(**params))

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

    available_commands = COMMANDS.keys() + COMMAND_ALIASES.keys()
    output_type = options.output_type.lower()
    if output_type not in available_commands:
        sys.stderr.write('Error: invalid output type ({})\n'.format(
                         options.output_type))
        return 1

    command_type = COMMAND_ALIASES.get(output_type, output_type)
    rules = merge_yaml(options.paths, (command_type in SECGROUP_COMMANDS))
    output_rules = generate_commands(command_type, rules, options.group)

    sys.stdout.write('{}\n'.format('\n'.join(output_rules)))
    return 0


def main():
    sys.exit(run(*sys.argv[1:]))


if __name__ == '__main__':
    main()
