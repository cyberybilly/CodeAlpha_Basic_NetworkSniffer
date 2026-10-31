"""CodeAlpha Task 1: a bounded, educational network packet sniffer."""

import argparse

from scapy.all import conf, sniff, IP, IPv6, TCP, UDP, ICMP, Raw


def display_packet(packet):
    """Print headers and at most 64 bytes of undecoded payload."""
    print("\n--- Packet ---")
    if IP in packet:
        network = packet[IP]
    elif IPv6 in packet:
        network = packet[IPv6]
    else:
        print("Other packet:", packet.summary())
        return

    if TCP in packet:
        protocol = "TCP"
    elif UDP in packet:
        protocol = "UDP"
    elif ICMP in packet:
        protocol = "ICMP"
    else:
        protocol = "Other IP protocol"

    print("Source IP:", network.src)
    print("Destination IP:", network.dst)
    print("Protocol:", protocol)
    print("Packet size:", len(packet), "bytes")

    if TCP in packet or UDP in packet:
        transport = packet[TCP] if TCP in packet else packet[UDP]
        print("Source port:", transport.sport)
        print("Destination port:", transport.dport)
    if TCP in packet:
        print("TCP flags:", packet[TCP].flags)
    if ICMP in packet:
        print("ICMP type:", packet[ICMP].type)
        print("ICMP code:", packet[ICMP].code)

    if Raw in packet:
        payload = packet[Raw].load
        print("Raw payload size:", len(payload), "bytes")
        print("Payload preview (up to 64 bytes):", repr(payload[:64]))
    else:
        print("Raw payload: no undecoded data available")


def run_demo():
    """Construct examples in memory; do not send or capture traffic."""
    print("DEMO: constructed packets only; nothing is transmitted.")
    examples = [
        IP(src="192.0.2.10", dst="192.0.2.20")
        / TCP(sport=50000, dport=8080, flags="PA")
        / Raw(load=b"Hello Bilkisu! This is our practice payload."),
        IP(src="192.0.2.10", dst="192.0.2.20")
        / UDP(sport=50001, dport=9999) / Raw(load=b"Practice UDP message"),
        IP(src="192.0.2.10", dst="192.0.2.20") / ICMP(type=8, code=0),
    ]
    for packet in examples:
        display_packet(packet)
    print("\nDemo finished.")


def positive_integer(value):
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("Use a number greater than zero.")
    return number


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--demo", action="store_true", help="Display local practice packets")
    mode.add_argument("--list-interfaces", action="store_true", help="List network interfaces")
    parser.add_argument("--iface", type=int, help="Interface index from --list-interfaces")
    parser.add_argument("--count", type=positive_integer, default=5, help="Packet limit (default: 5)")
    parser.add_argument("--timeout", type=positive_integer, default=20, help="Time limit in seconds (default: 20)")
    args = parser.parse_args()

    if args.demo:
        run_demo()
        return
    if args.list_interfaces:
        print(conf.ifaces)
        return
    if args.iface is None:
        parser.error("Choose an interface with --iface; use --list-interfaces to find its index.")

    try:
        interface = conf.ifaces.dev_from_index(args.iface)
    except (ValueError, KeyError) as error:
        parser.error(f"Interface {args.iface} is unavailable. Run --list-interfaces again. {error}")

    print(f"Capturing up to {args.count} packets for a maximum of {args.timeout} seconds...")
    try:
        sniff(iface=interface, count=args.count, timeout=args.timeout,
              prn=display_packet, store=False, promisc=False)
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")
    except (OSError, RuntimeError) as error:
        parser.exit(1, f"Capture failed: {error}\nCheck Npcap and capture permissions.\n")
    else:
        print("\nCapture finished.")


if __name__ == "__main__":
    main()
