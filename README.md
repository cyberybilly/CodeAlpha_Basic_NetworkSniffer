# CodeAlpha Network Sniffer

An educational Python packet sniffer developed by Bilkisu Ishaq Muhammad for CodeAlpha Cyber Security Internship Task 1.

## What it does

- Captures traffic on a selected network interface using Scapy.
- Displays IPv4/IPv6 source and destination addresses and captured packet size.
- Identifies TCP, UDP and IPv4 ICMP; other IP protocols receive a generic label.
- Displays TCP/UDP ports, TCP flags, and ICMP type and code.
- Previews up to 64 bytes from Scapy's undecoded Raw layer.
- Stops after a packet limit or timeout (defaults: 5 packets or 20 seconds).
- Offers an offline demo with constructed TCP, UDP and ICMP examples.

## Files

- `sniffer.py`: the program.
- `requirements.txt`: the Scapy dependency used for this project.
- `.gitignore`: excludes virtual environments, backups and captures from Git.
- `README.md`: installation, usage, validation and limitations.

## Windows setup

Install Python from https://www.python.org/downloads/ and Npcap from https://npcap.com/#download.
For Scapy, leave Npcap's WinPcap compatibility mode off. Monitor mode is unnecessary for this project.

Open Command Prompt in the project folder and run these commands separately:

```text
python -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
```

If you already created and activated the environment during the project, use that environment.
To return to the original project folder on the author's laptop:

```text
cd C:\Users\HP\CodeAlpha_NetworkSniffer
.venv\Scripts\activate
```

## Run the offline demo

```text
python sniffer.py --demo
```

This constructs three packets in memory and displays their fields. It does not transmit or capture traffic, and does not require an interface selection. Python/Scapy may still enumerate local interfaces during import.

Expected examples:

| Protocol | Details |
| --- | --- |
| TCP | Source port 50000, destination port 8080, flags PA, 44-byte message |
| UDP | Source port 50001, destination port 9999, 20-byte message |
| ICMP | Type 8, code 0: echo request, without a Raw payload |

The addresses 192.0.2.10 and 192.0.2.20 are documentation examples. The program constructs these packets without sending them.

## Run a live capture

List the available adapters:

```text
python sniffer.py --list-interfaces
```

Choose the index of your connected adapter. For example, if it is index 9:

```text
python sniffer.py --iface 9
```

Generate normal traffic on your own computer, for example by refreshing a webpage.
The capture stops after five packets or 20 seconds, whichever occurs first. Press Ctrl+C to stop early.
Interface indices can change: check the list again when changing networks or computers.

To change both limits:

```text
python sniffer.py --iface 9 --count 10 --timeout 30
```

To see all command options:

```text
python sniffer.py --help
```

Use live capture only on your own device or a network where you have permission.
If Npcap was installed with administrator-only access, run Command Prompt as administrator, return to the project folder, and activate its environment before capturing.

## How the code works

1. `argparse` reads your command options and checks capture limits.
2. `main()` selects demo mode, interface listing, or live capture.
3. `sniff()` receives packets and calls `display_packet()` for each one through its `prn` argument.
4. `display_packet()` checks packet layers, extracts fields, and prints the result.
5. `store=False` avoids accumulating captured packets in a collection. `promisc=False` uses normal capture mode; broadcast and multicast packets may still be visible.
6. The `if __name__ == "__main__"` guard starts the command interface only when the script is run directly. Importing the module does not start a capture.

## Understanding the output

- Source/destination IP: the packet's sending and receiving network addresses.
- Source/destination port: TCP/UDP endpoints used by applications and services.
- TCP flag A: acknowledgement. PA: PSH and ACK together. Flags alone do not prove application content or intent.
- Packet size: size of the captured packet, including the headers Scapy received. Capture location and network offloading can affect observed sizes.
- Raw payload: bytes Scapy has left undecoded, shown with escaped characters where necessary. A missing Raw layer does not always mean no application data; Scapy may have decoded it into another layer.

## Validation record

During guided development on 27-28 October 2026:

- Windows Command Prompt reported Python 3.15.2 and Scapy 2.8.0.
- Npcap-backed interface listing worked on the author's laptop.
- The revised offline demo displayed TCP, UDP and ICMP fields and known payloads correctly on Windows.
- Live capture on interface 9 displayed five TCP packets with addresses, ports, flags, sizes and Raw previews. A packet without a Raw layer was also displayed correctly.
- Additional offline checks in a separate Python 3.12 environment exercised TCP, UDP, ICMP, IPv6, non-IP packets, the preview length limit, argument validation and capture settings. Network discovery was disabled and the capture function was mocked for these checks.

Live UDP, ICMP and IPv6 capture have not been demonstrated in the recorded Windows checks. Offline examples validate field handling, not live delivery or a complete protocol implementation.

## Limitations

- This is a basic learning tool, not an intrusion detection system.
- It does not decrypt HTTPS or other encrypted traffic, reassemble streams, or identify applications reliably from ports alone.
- The preview is limited to 64 bytes of the Raw layer; it is not a complete application message.
- ICMPv6 receives the generic other-IP-protocol label in this version.
- Non-IP packets receive a one-line summary instead of IP fields.
- It prints output to the terminal and does not save packet captures. Terminal output can contain sensitive data; use constructed demo output for public examples where possible.
- Packet limits count all captured packets, including non-IP packets.

## Troubleshooting

- **No module named scapy:** activate `.venv`, then run `python -m pip install -r requirements.txt`.
- **Interface unavailable:** rerun `--list-interfaces` and select a current index.
- **Capture permissions or Npcap error:** check the Npcap installation and any administrator-only restriction.
- **No packets before timeout:** confirm the selected adapter is connected, generate traffic, or increase the timeout.
- **Running without --iface shows usage:** choose `--demo`, `--list-interfaces`, or provide `--iface NUMBER`.

## Submission preparation

Create a GitHub repository named `CodeAlpha_NetworkSniffer` and include these four project files. Exclude `.venv`, backups and real packet data. In the explanation video, show the purpose, offline demo, interface selection, a permitted short live capture, and the limitations. Include the GitHub link in the required LinkedIn post and submit through the internship's designated form.

## References

- Scapy installation: https://scapy.readthedocs.io/en/latest/installation.html
- Scapy usage: https://scapy.readthedocs.io/en/stable/usage.html
- Python virtual environments: https://docs.python.org/3/library/venv.html
- Npcap: https://npcap.com/
