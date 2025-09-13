# packet_sniffer_windows.py
"""
Windows-friendly packet sniffer (educational).

Requirements (Windows):
  1. Install Npcap (https://nmap.org/npcap/) — choose WinPcap-compatible mode if prompted.
  2. Install scapy in your Python environment:
       pip install scapy
  3. Run VS Code / PowerShell as Administrator.

Usage examples (run in VS Code terminal as Admin):
  # list interfaces
  python packet_sniffer_windows.py --list-ifaces

  # sniff 100 packets on interface "Ethernet" and save to capture.pcap
  python packet_sniffer_windows.py --iface "Ethernet" --count 100 --save capture.pcap

  # sniff indefinitely on default iface (Ctrl+C to stop)
  python packet_sniffer_windows.py --iface "Wi-Fi"

Notes:
- This is educational. Only sniff traffic you own/have permission to inspect.
"""

from __future__ import annotations
import argparse
import datetime
import sys

# Windows admin check
def is_windows_admin() -> bool:
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# Try importing scapy (required on Windows)
USE_SCAPY = False
try:
    from scapy.all import sniff, wrpcap, Ether, IP, TCP, UDP, ICMP, get_if_list, get_if_addr  # type: ignore

    USE_SCAPY = True
except Exception as e:
    USE_SCAPY = False
    _scapy_import_error = e


def human_time():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def scapy_packet_handler(pkt):
    """Callback for `sniff` — prints a concise human-readable summary."""
    ts = human_time()
    try:
        if pkt.haslayer(IP):
            ip = pkt[IP]
            src = ip.src
            dst = ip.dst
            proto = ip.proto
            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                summary = f"TCP {src}:{tcp.sport} -> {dst}:{tcp.dport} flags={tcp.sprintf('%flags%')}"
            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                summary = f"UDP {src}:{udp.sport} -> {dst}:{udp.dport}"
            elif pkt.haslayer(ICMP):
                summary = f"ICMP {src} -> {dst} type={pkt[ICMP].type}"
            else:
                summary = f"IP proto={proto} {src} -> {dst}"
        elif pkt.haslayer(Ether):
            eth = pkt[Ether]
            summary = f"ETH {eth.src} -> {eth.dst} (ethertype=0x{eth.type:04x})"
        else:
            summary = pkt.summary()
    except Exception:
        # In case some packets cause unexpected read errors
        summary = pkt.summary()

    print(f"[{ts}] {summary}")


def list_interfaces():
    if not USE_SCAPY:
        print("[!] Scapy is not available; cannot list interfaces.")
        print("    Make sure scapy is installed in your environment: pip install scapy")
        return
    try:
        ifaces = get_if_list()
        print("[*] Available network interfaces (Scapy):")
        for i, ifname in enumerate(ifaces, 1):
            addr = ""
            try:
                addr = get_if_addr(ifname)
            except Exception:
                addr = ""
            print(f"  {i:02d}. {ifname} {('(' + addr + ')') if addr else ''}")
    except Exception as e:
        print("[!] Failed to list interfaces:", e)


def run_scapy_capture(iface: str | None, count: int, save: str | None, timeout: int | None):
    if not USE_SCAPY:
        print("[!] Scapy is not installed. Please install scapy and ensure Npcap is installed on Windows.")
        print("    pip install scapy")
        print("    Download Npcap: https://nmap.org/npcap/")
        print("    Then run this script in an Administrator terminal.")
        return

    if not is_windows_admin():
        print("[!] Warning: Running without Administrator privileges may prevent scapy/npcap from capturing packets.")
        print("    Re-run VS Code / terminal as Administrator for reliable captures.\n")

    print("[*] Starting capture (scapy). Press Ctrl+C to stop.")
    print(f"    iface: {iface or '<default>'}  count: {count or 'unlimited'}  save: {save or 'no'}\n")

    try:
        packets = sniff(iface=iface, prn=scapy_packet_handler, count=count if count > 0 else 0, timeout=timeout)
    except PermissionError as pe:
        print("[!] Permission error while sniffing. Are you running as Administrator and is Npcap installed?")
        print("    Details:", pe)
        return
    except Exception as e:
        print("[!] Error while sniffing:", e)
        return

    print(f"\n[*] Capture finished. Packets captured: {len(packets)}")
    if save:
        try:
            wrpcap(save, packets)
            print(f"[*] Saved capture to: {save}")
        except Exception as e:
            print("[!] Failed to save pcap:", e)


def parse_args():
    ap = argparse.ArgumentParser(description="Windows packet sniffer (educational). Requires scapy + Npcap.")
    ap.add_argument("--iface", "-i", help="Interface name (e.g., 'Ethernet' or 'Wi-Fi'). If omitted, scapy chooses default.")
    ap.add_argument("--count", "-c", type=int, default=0, help="Number of packets to capture (0 means unlimited).")
    ap.add_argument("--save", "-w", help="Optional: save captured packets to a pcap file (requires scapy).")
    ap.add_argument("--timeout", "-t", type=int, help="Optional timeout in seconds (scapy mode).")
    ap.add_argument("--list-ifaces", action="store_true", help="List available network interfaces (scapy).")
    return ap.parse_args()


def main():
    args = parse_args()

    if args.list_ifaces:
        list_interfaces()
        return

    if not USE_SCAPY:
        print("[!] Scapy import failed.")
        print("    Import error was:", getattr(sys, "_scapy_import_error", "unknown"))
        print("    To fix on Windows:")
        print("      1) Install Npcap from https://nmap.org/npcap/ (choose WinPcap-compatible mode).")
        print("      2) Install scapy in your Python environment: pip install scapy")
        print("      3) Run this script from an Administrator terminal.")
        return

    run_scapy_capture(args.iface, args.count, args.save, args.timeout)


if __name__ == "__main__":
    main()
