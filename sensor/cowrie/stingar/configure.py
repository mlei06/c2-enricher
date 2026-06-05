import argparse
import configparser
from cymruwhois import Client


def get_asn(ip_addr):
    c = Client()
    r = c.lookup(ip_addr)
    return r.asn


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("--fluent-host", default="fluentbit",
                        help="Hostname or IP address of fluentbit container.")
    parser.add_argument("--fluent-port", default=24284,
                        help="Port number of the fluentbit process.")
    parser.add_argument("--fluent-app", default="stingar",
                        help="App name for fluentbit process.")
    parser.add_argument("--hostname", default="stingar",
                        help="Hostname for the honeypot.")
    parser.add_argument("--ip-addr",
                        help="IP address of the honeypot.")
    parser.add_argument("--asn",
                        help="ASN of the honeypot.")
    parser.add_argument("--ident",
                        help="Unique identifier of the honeypot.")
    parser.add_argument("--tags",
                        help="Tags associated with honeypot.")
    parser.add_argument("--template-file",
                        help="Configuration template file for honeypot.")
    parser.add_argument("--reported-ssh-port", default="22",
                        help="SSH port to use for reporting.")
    parser.add_argument("--reported-telnet-port", default="23",
                        help="Telnet port to use for reporting")
    parser.add_argument("--config-file",
                        help="Configuration file path for honeypot.")
    args = parser.parse_args()

    # interpolation=None: cowrie.cfg.dist contains literal % (log/date formats)
    # and ${section:key} refs that cowrie's own ExtendedInterpolation resolves
    # at runtime — we must preserve them verbatim, not interpolate here.
    config = configparser.ConfigParser(interpolation=None)
    if not config.read(args.template_file):
        raise SystemExit(f"configure: template not found: {args.template_file}")

    # Update honeypot config options
    config['honeypot']['hostname'] = args.hostname


    # Update Fluentd config options
    config['output_stingar']['fluent_host'] = args.fluent_host
    config['output_stingar']['fluent_port'] = args.fluent_port
    config['output_stingar']['app'] = args.fluent_app
    config['output_stingar']['hostname'] = args.hostname
    config['output_stingar']['ip_addr'] = args.ip_addr
    config['output_stingar']['identifier'] = args.ident
    config['output_stingar']['tags'] = args.tags

    if args.asn:
        config['output_stingar']['asn'] = args.asn
    else:
        config['output_stingar']['asn'] = ""
        # config['output_stingar']['asn'] = get_asn(args.ip_addr)

    if args.reported_ssh_port:
        config['honeypot']['reported_ssh_port'] = args.reported_ssh_port
    if args.reported_telnet_port:
        config['telnet']['reported_port'] = args.reported_telnet_port

    with open(args.config_file, 'w') as configfile:
        config.write(configfile)


if __name__ == "__main__":
    main()
