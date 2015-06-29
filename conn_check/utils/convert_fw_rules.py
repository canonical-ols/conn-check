from argparse import ArgumentParser
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


RULES_GENERATORS = {}


def run(*args):
    parser = ArgumentParser()
    parser.add_argument('-t', '--type', dest='output_type', required=True,
                        help="Rules output type, e.g. neutron, aws, iptables")
    parser.add_argument("paths", nargs='+',
                        help="Paths to YAML files to combine/parse.")
    options = parser.parse_args(list(args))

    rules = merge_yaml(options.paths)
    output_rules = RULES_GENERATORS.get(options.output_type,
                                        lambda r: None)(rules)
    if output_rules is not None:
        sys.stdout.write(output_rules)
        return 0
    else:
        sys.stderr.write('Error: invalid output type ({})\n'.format(
                         options.output_type))
        return 1


def main():
    sys.exit(run(*sys.argv[1:]))


if __name__ == '__main__':
    main()
