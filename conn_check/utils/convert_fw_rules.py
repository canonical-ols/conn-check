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


def output_aws_rules(rules, **kwargs):
    group_id = kwargs.get('group_id', '$AWS_SECGROUP_ID')
    cmd = ('authorize-security-group-egress --group-id {group_id} --protocol'
           ' {protocol} --port {port} --cidr {cidr}')
    output = []
    for rule in rules:
        for port in rule['ports']:
            params = {
                'group_id': group_id,
                'cidr': str(IPNetwork(gethostbyname(rule['to_host'])).cidr),
                'port': port,
            }
            params.update(rule)
            output.append(cmd.format(**params))

    return '\n'.join(output)


def output_neutron_rules(rules):
    output = []
    return '\n'.join(output)


def output_iptables_rules(rules):
    output = []
    return '\n'.join(output)


RULES_GENERATORS = {
    'aws': output_aws_rules,
    'amazon': output_aws_rules,
    'ec2': output_aws_rules,
    'neutron': output_neutron_rules,
    'openstack': output_neutron_rules,
    'os': output_neutron_rules,
    'iptables': output_iptables_rules,
}


def run(*args):
    parser = ArgumentParser()
    parser.add_argument('-t', '--type', dest='output_type', required=True,
                        help="Rules output type, e.g. neutron, aws, iptables.")
    parser.add_argument("paths", nargs='+',
                        help="Paths to YAML files to combine/parse.")
    parser.add_argument('--aws-group-id', dest='aws_group_id', required=False,
                        help="AWS security group ID if output is aws/amazon.")
    options = parser.parse_args(list(args))

    kwargs = {}
    if options.aws_group_id:
        kwargs['group_id'] = options.aws_group_id

    rules = merge_yaml(options.paths)
    output_rules = RULES_GENERATORS.get(options.output_type.lower(),
                                        lambda r: None)(rules, **kwargs)
    if output_rules is not None:
        sys.stdout.write('{}\n'.format(output_rules))
        return 0
    else:
        sys.stderr.write('Error: invalid output type ({})\n'.format(
                         options.output_type))
        return 1


def main():
    sys.exit(run(*sys.argv[1:]))


if __name__ == '__main__':
    main()
