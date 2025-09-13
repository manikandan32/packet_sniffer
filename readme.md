# Windows Packet Sniffer 🪟🔍

A Windows-friendly packet sniffer written in Python using **Scapy**. This educational tool captures live network packets, displays essential packet fields (source/destination IPs, ports, protocol), and can save captures to PCAP files for analysis in Wireshark.

> ⚠️ **Legal & ethical notice:** Only capture traffic on networks and devices you own or where you have explicit permission. Unauthorized packet sniffing is illegal and unethical.

---

## Highlights ✨

- Built for learning and demonstration — small, readable, and well-commented.
- Supports TCP, UDP, ICMP and other protocols as visible via Scapy.
- Lists network interfaces available on Windows (requires Npcap).
- Options to limit packet count, set a timeout, and filter by protocol/address.
- Export captured packets to a `.pcap` file (open in Wireshark for deep inspection).
- Works best with Administrator privileges on Windows.

---

## Requirements 🧩

- Windows 10/11 (Administrator privileges recommended)
- Python 3.8+ (latest stable Python 3.x recommended)
- [Npcap](https://nmap.org/npcap/) installed (WinPcap is deprecated)
- `scapy` Python package

Install Python packages with pip:

```bash
pip install scapy
```

Make sure Npcap is installed and that you run the script from an elevated (Administrator) terminal. Npcap provides the low-level packet capture driver required for raw packet access on Windows.

---

## Features & CLI options ⚙️

Typical options provided by the script (adjust flags/names depending on your implementation):

- `--list-interfaces` — Show available network interfaces and exit.
- `--interface <name>` — Capture packets on the specified interface.
- `--count <n>` — Stop after capturing `n` packets.
- `--timeout <seconds>` — Stop after `t` seconds (if provided).
- `--filter <BPF>` — Optional Berkeley Packet Filter (e.g., `tcp`, `udp and port 53`).
- `--output <file.pcap>` — Save captured packets to a PCAP file.
- `--promiscuous` — (Optional) enable promiscuous mode if supported.

---

## Example usage 💡

Run with admin privileges in PowerShell or CMD:

```powershell
# List interfaces
python packet_sniffer.py --list-interfaces

# Capture 100 packets on interface 'Ethernet' and save to capture.pcap
python packet_sniffer.py --interface "Ethernet" --count 100 --output capture.pcap

# Capture for 30 seconds with a BPF filter for TCP
python packet_sniffer.py --interface "Wi-Fi" --timeout 30 --filter "tcp"
```

Open the resulting `capture.pcap` in Wireshark for detailed analysis.

---

## How it works (brief) 🧠

1. Uses Scapy's sniffing APIs to capture packets from a chosen interface.
2. For each packet, prints human-readable summaries (timestamp, src/dst, proto, ports).
3. Optionally saves packet objects into a list and writes them to a PCAP file using Scapy's `wrpcap()`.

This is a simple, synchronous demonstration. For higher performance or production uses, consider asynchronous capture or native pcap bindings.

---

## Troubleshooting 🛠️

- **No interfaces listed**: Ensure Npcap is installed and you have restarted the PC after installation. Run the script as Administrator.
- **Permission errors**: Launch PowerShell or CMD as Administrator.
- **Scapy errors on Windows**: Use a recent Scapy version and confirm Npcap is installed. Running `scapy.config.conf.use_pcap = True` may help in some environments.

---

## Next improvements / roadmap 🚀

- Add a GUI (Tkinter or PySimpleGUI) for easier interaction.
- Add asynchronous capture for higher throughput.
- Add protocol-specific parsers and banner grabbing for service identification.
- Add export to CSV/JSON summary for quick reporting.
- Implement a safe/rate-limited mode to avoid flooding networks.

---

## Contributing

Contributions are welcome. Please open issues for bugs or feature requests and submit PRs with clear descriptions and tests when applicable.

---

## License

Add an open license (MIT, Apache-2.0, etc.). MIT is a good permissive default.

---

*Made for learning and responsible security research.*

