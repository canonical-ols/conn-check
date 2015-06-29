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


def run(*args):
    parser = ArgumentParser()
    parser.add_argument("paths", nargs='*',
                        help="Paths to YAML files to merge.")
    options = parser.parse_args(list(args))

    sys.stdout.write(yaml.dump(merge_yaml(options.paths)))

    return 0


def main():
    sys.exit(run(*sys.argv[1:]))


if __name__ == '__main__':
    main()
