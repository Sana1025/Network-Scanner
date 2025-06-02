import tkinter as tk
from tkinter import scrolledtext, messagebox
from scapy.all import ARP, Ether, srp
import nmap
import threading

# --- Network Scanner ---
def scan_local_devices(ip_range):
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = srp(packet, timeout=2, verbose=0)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    return devices

# --- Port Scanner ---
def scan_ports(ip):
    scanner = nmap.PortScanner()
    scanner.scan(ip, '1-1024', '-T4')
    open_ports = []

    if ip in scanner.all_hosts():
        for proto in scanner[ip].all_protocols():
            for port in scanner[ip][proto].keys():
                state = scanner[ip][proto][port]['state']
                if state == 'open':
                    open_ports.append((port, scanner[ip][proto][port]['name']))
    return open_ports

# --- Vulnerability Checker ---
def detect_vulnerabilities(open_ports):
    vulns = []
    for port, service in open_ports:
        if service in ['ftp', 'telnet', 'smtp', 'pop3']:
            vulns.append(f"⚠️ Unsecured protocol: {service.upper()} on port {port}")
        if port == 80:
            vulns.append("🔎 HTTP open (check for outdated services)")
        if port == 22:
            vulns.append("🔐 SSH open (ensure it’s secured properly)")
    return vulns

# --- Run the Scan Process ---
def run_scan():
    ip_range = entry_ip.get().strip()
    if not ip_range:
        messagebox.showerror("Input Error", "Please enter a valid IP range.")
        return

    text_output.delete("1.0", tk.END)
    text_output.insert(tk.END, f"Scanning network: {ip_range}...\n\n")

    try:
        devices = scan_local_devices(ip_range)
        if not devices:
            text_output.insert(tk.END, "No devices found.\n")
            return

        text_output.insert(tk.END, "📡 Devices Found:\n")
        for device in devices:
            text_output.insert(tk.END, f" - {device['ip']} ({device['mac']})\n")

        for device in devices:
            ip = device['ip']
            text_output.insert(tk.END, f"\n🔍 Scanning {ip}...\n")
            ports = scan_ports(ip)
            text_output.insert(tk.END, f"  Open Ports: {ports if ports else 'None'}\n")

            vulns = detect_vulnerabilities(ports)
            if vulns:
                text_output.insert(tk.END, "  🚨 Vulnerabilities:\n")
                for v in vulns:
                    text_output.insert(tk.END, f"   {v}\n")
            else:
                text_output.insert(tk.END, "  ✅ No major issues.\n")

        text_output.insert(tk.END, "\n✅ Scan Complete.\n")

    except Exception as e:
        messagebox.showerror("Error", str(e))

# --- Thread Wrapper for Scan ---
def start_scan_thread():
    threading.Thread(target=run_scan, daemon=True).start()

# --- GUI Setup ---
root = tk.Tk()
root.title("Local Network Vulnerability Scanner")
root.geometry("700x500")

frame = tk.Frame(root)
frame.pack(pady=10)

tk.Label(frame, text="Enter IP Range (e.g., 192.168.1.0/24):").pack()
entry_ip = tk.Entry(frame, width=40)
entry_ip.pack(pady=5)

tk.Button(frame, text="Start Scan", command=start_scan_thread, bg="#1f6aa5", fg="white", padx=10).pack()

text_output = scrolledtext.ScrolledText(root, width=80, height=25, wrap=tk.WORD)
text_output.pack(pady=10)

root.mainloop()
