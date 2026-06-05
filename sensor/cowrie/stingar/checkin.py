import datetime
import argparse
from cymruwhois import Client
from fluent.sender import FluentSender


SENSOR_TOPIC = "sensors"


def get_asn(ip_addr):
    c = Client()
    r = c.lookup(ip_addr)
    return r.asn


def build_tags(tag_str):
    tags = {}
    for tag in tag_str.split(","):
        try:
            k, v = tag.strip().split(":")
            tags[k.strip()] = v.strip()
        except ValueError:
            tags.setdefault('misc', []).append(tag.strip())
    return tags


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--ident",
                        help="Unique identifier of the honeypot.")
    parser.add_argument("-n", "--hostname",
                        help="Hostname of the honeypot.")
    parser.add_argument("-t", "--type",
                        help="Honeypot type.")
    parser.add_argument("-a", "--address",
                        help="IP address of the honeypot.")
    parser.add_argument("--asn",
                        help="ASN of the honeypot.")
    parser.add_argument("--fluent-host", default="fluentbit",
                        help="Hostname of Fluent Bit server")
    parser.add_argument("--fluent-port", type=int, default=24284,
                        help="Port of Fluent Bit server")
    parser.add_argument("--fluent-app", default="stingar",
                        help="Application name for Fluent Bit server")
    parser.add_argument("--tags", help="Comma separated tags for honeypot.")
    args = parser.parse_args()

    data = {"uuid": args.ident,
            "hostname": args.hostname,
            "honeypot": args.type,
            "ip": args.address,
            "created": datetime.datetime.utcnow().isoformat() + "Z",
            "updated": datetime.datetime.utcnow().isoformat() + "Z",
            "tags": build_tags(args.tags)}

    if args.asn:
        data['asn'] = args.asn
    else:
        data['asn'] = ""
    #     data['asn'] = get_asn(args.hostname)

    sender = FluentSender(args.fluent_app,
                          host=args.fluent_host,
                          port=args.fluent_port)

    sender.emit(SENSOR_TOPIC, data)
    return 0


if __name__ == "__main__":
    main()
