#!/usr/bin/env python3

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import queue
from datetime import datetime
from collections import defaultdict
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR, Raw, conf, get_if_list, hexdump
import json
import io
from contextlib import redirect_stdout

stop_sniffing = threading.Event()
sniffer_thread = None
packet_queue = queue.Queue()
statistics = defaultdict(int)
captured_packets = []
pcap_filename = None
output_filename = None

class NetworkSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Sniffer Tool (Enhanced)")
        self.root.geometry("1200x800")

        control_frame = ttk.Frame(root)
        control_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)

        ttk.Label(control_frame, text="Interface:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.interface_var = tk.StringVar()
        self.interface_combo = ttk.Combobox(control_frame, textvariable=self.interface_var, state="readonly")
        self.interface_combo.grid(row=0, column=1, sticky=tk.W, padx=(0, 10))
        self.populate_interfaces()

        ttk.Label(control_frame, text="Filter (BPF):").grid(row=0, column=2, sticky=tk.W, padx=(10, 5))
        self.filter_var = tk.StringVar(value="")
        ttk.Entry(control_frame, textvariable=self.filter_var, width=30).grid(row=0, column=3, sticky=tk.W, padx=(0, 10))

        self.start_button = ttk.Button(control_frame, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.grid(row=0, column=4, padx=(10, 5))

        self.stop_button = ttk.Button(control_frame, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=5, padx=(0, 5))

        self.save_pcap_button = ttk.Button(control_frame, text="Save PCAP", command=self.save_pcap)
        self.save_pcap_button.grid(row=0, column=6, padx=(0, 5))

        self.save_txt_button = ttk.Button(control_frame, text="Save Log", command=self.save_log)
        self.save_txt_button.grid(row=0, column=7)
        
        self.clear_button = ttk.Button(control_frame, text="Clear", command=self.clear_capture, state=tk.DISABLED)
        self.clear_button.grid(row=0, column=8, padx=(5,0))

        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        log_frame = ttk.Frame(self.notebook)
        self.notebook.add(log_frame, text="Log")
        self.log_text = scrolledtext.ScrolledText(log_frame, state=tk.DISABLED)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        packets_frame = ttk.Frame(self.notebook)
        self.notebook.add(packets_frame, text="Packets")

        columns = ("#", "Time", "Source IP", "Dest IP", "Protocol", "Length", "Info")
        self.packet_tree = ttk.Treeview(packets_frame, columns=columns, show="headings", height=15)
        for col in columns:
            self.packet_tree.heading(col, text=col)
            if col == "#":
                self.packet_tree.column(col, width=50, anchor=tk.CENTER)
            elif col == "Time":
                self.packet_tree.column(col, width=150, anchor=tk.CENTER)
            elif col == "Source IP":
                self.packet_tree.column(col, width=120, anchor=tk.W)
            elif col == "Dest IP":
                self.packet_tree.column(col, width=120, anchor=tk.W)
            elif col == "Protocol":
                self.packet_tree.column(col, width=80, anchor=tk.CENTER)
            elif col == "Length":
                self.packet_tree.column(col, width=70, anchor=tk.CENTER)
            elif col == "Info":
                self.packet_tree.column(col, width=300, anchor=tk.W)
        
        self.packet_tree.tag_configure("TCP", background="#EEF5FF")
        self.packet_tree.tag_configure("UDP", background="#F0FFF0")
        self.packet_tree.tag_configure("ICMP", background="#FFFFE8")
        self.packet_tree.tag_configure("ARP", background="#F5F0F5")
        self.packet_tree.tag_configure("HTTP", background="#D0FFD0", foreground="#005000")
        self.packet_tree.tag_configure("DNS", background="#FFF0E0")
        self.packet_tree.tag_configure("Other", background="#FFFFFF")

        self.packet_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        tree_scrollbar = ttk.Scrollbar(packets_frame, orient=tk.VERTICAL, command=self.packet_tree.yview)
        self.packet_tree.configure(yscroll=tree_scrollbar.set)
        tree_scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=5)

        self.packet_tree.bind("<<TreeviewSelect>>", self.on_packet_select)

        details_frame = ttk.Frame(self.notebook)
        self.notebook.add(details_frame, text="Details")
        self.details_text = scrolledtext.ScrolledText(details_frame, state=tk.DISABLED, font=("Courier New", 9))
        self.details_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        stats_frame = ttk.Frame(self.notebook)
        self.notebook.add(stats_frame, text="Statistics")
        self.stats_text = scrolledtext.ScrolledText(stats_frame, state=tk.DISABLED, font=("Courier New", 9))
        self.stats_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def populate_interfaces(self):
        interfaces = get_if_list()
        self.interface_combo['values'] = interfaces
        default_iface = conf.iface
        if default_iface in interfaces:
            self.interface_combo.set(default_iface)
        elif interfaces:
            self.interface_combo.set(interfaces[0])

    def log_message(self, message):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)

    def start_sniffing(self):
        global sniffer_thread, stop_sniffing, captured_packets, statistics
        if sniffer_thread and sniffer_thread.is_alive():
            messagebox.showwarning("Warning", "Sniffing is already in progress.")
            return

        stop_sniffing.clear()
        
        if not captured_packets:
             statistics = defaultdict(int)
             self.packet_tree.delete(*self.packet_tree.get_children())
             self.details_text.config(state=tk.NORMAL)
             self.details_text.delete(1.0, tk.END)
             self.details_text.config(state=tk.DISABLED)
             self.stats_text.config(state=tk.NORMAL)
             self.stats_text.delete(1.0, tk.END)
             self.stats_text.config(state=tk.DISABLED)

        interface = self.interface_var.get()
        bpf_filter = self.filter_var.get()

        if not interface:
            messagebox.showerror("Error", "Please select a network interface.")
            return

        self.log_message(f"[INFO] Starting sniffing on {interface} with filter '{bpf_filter}'...")
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.clear_button.config(state=tk.DISABLED)

        sniffer_thread = threading.Thread(
            target=self.sniff_packets,
            args=(interface, bpf_filter)
        )
        sniffer_thread.daemon = True
        
        self.update_stats_timer()
        
        sniffer_thread.start()

        self.process_queue()

    def stop_sniffing(self):
        global stop_sniffing
        stop_sniffing.set()
        self.log_message("[INFO] Stopping packet capture...")
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.clear_button.config(state=tk.NORMAL)
        
        self.update_stats()

    def clear_capture(self):
        global captured_packets, statistics
        
        if messagebox.askyesno("Confirm", "Are you sure you want to clear all captured data?"):
            captured_packets = []
            statistics = defaultdict(int)
            
            self.packet_tree.delete(*self.packet_tree.get_children())
            
            self.details_text.config(state=tk.NORMAL)
            self.details_text.delete(1.0, tk.END)
            self.details_text.config(state=tk.DISABLED)
            
            self.log_text.config(state=tk.NORMAL)
            self.log_text.delete(1.0, tk.END)
            self.log_text.config(state=tk.DISABLED)
            
            self.update_stats()
            
            self.log_message("[INFO] Capture data cleared.")
            self.clear_button.config(state=tk.DISABLED)

    def sniff_packets(self, interface, bpf_filter):
        try:
            sniff(
                iface=interface,
                filter=bpf_filter,
                prn=self.queue_packet,
                store=0,
                stop_filter=lambda x: stop_sniffing.is_set()
            )
        except Exception as e:
            packet_queue.put(("ERROR", str(e)))

    def queue_packet(self, packet):
        if not stop_sniffing.is_set():
            packet_queue.put(("PACKET", packet))

    def process_queue(self):
        global statistics, captured_packets
        try:
            while True:
                item_type, item_data = packet_queue.get_nowait()

                if item_type == "PACKET":
                    packet = item_data
                    captured_packets.append(packet)
                    packet_info = self.analyze_packet(packet)

                    l3_proto = packet_info.get("l3_protocol", "Other")
                    l4_proto = packet_info.get("l4_protocol", "Other")
                    statistics[l3_proto] += 1
                    if l3_proto in ["IP", "IPv6"]:
                         statistics[l4_proto] += 1
                         if "src_ip" in packet_info:
                             statistics[f"SRC_{packet_info['src_ip']}"] += 1
                         if "dst_ip" in packet_info:
                             statistics[f"DST_{packet_info['dst_ip']}"] += 1
                    elif l3_proto == "ARP":
                         statistics["ARP"] += 1
                    else:
                         statistics["Other"] += 1

                    self.update_gui_elements(packet_info)

                elif item_type == "ERROR":
                    self.log_message(f"[ERROR] Sniffing thread error: {item_data}")
                    self.start_button.config(state=tk.NORMAL)
                    self.stop_button.config(state=tk.DISABLED)
                    break 

        except queue.Empty:
            pass 

        if not stop_sniffing.is_set() or not packet_queue.empty():
            self.root.after(50, self.process_queue)

    def analyze_packet(self, packet):
        packet_info = {
            "timestamp": datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S.%f'),
            "length": len(packet),
            "summary": packet.summary(),
            "tag": "Other"
        }

        if IP in packet:
            packet_info["l3_protocol"] = "IP"
            packet_info["src_ip"] = packet[IP].src
            packet_info["dst_ip"] = packet[IP].dst
            l4_layer = packet[IP]
        elif IPv6 in packet:
            packet_info["l3_protocol"] = "IPv6"
            packet_info["src_ip"] = packet[IPv6].src
            packet_info["dst_ip"] = packet[IPv6].dst
            l4_layer = packet[IPv6]
        elif ARP in packet:
            packet_info["l3_protocol"] = "ARP"
            packet_info["tag"] = "ARP"
            packet_info["arp_op"] = "Request" if packet[ARP].op == 1 else "Reply"
            packet_info["info"] = f"ARP {packet_info['arp_op']} {packet[ARP].psrc} -> {packet[ARP].pdst}"
            return packet_info
        else:
            packet_info["l3_protocol"] = "Other"
            packet_info["info"] = packet_info["summary"]
            return packet_info

        if TCP in l4_layer:
            packet_info["l4_protocol"] = "TCP"
            packet_info["tag"] = "TCP"
            packet_info["sport"] = l4_layer[TCP].sport
            packet_info["dport"] = l4_layer[TCP].dport
            packet_info["tcp_flags"] = l4_layer[TCP].flags.flagrepr()
            packet_info["info"] = f"TCP {packet_info['sport']} -> {packet_info['dport']} [{packet_info['tcp_flags']}]"
            
            if (packet_info["sport"] == 80 or packet_info["dport"] == 80) and l4_layer.haslayer(Raw):
                try:
                    raw_data = l4_layer[Raw].load.decode('utf-8', errors='ignore')
                    if raw_data.startswith("GET") or raw_data.startswith("POST") or raw_data.startswith("HTTP/"):
                        packet_info["tag"] = "HTTP"
                        packet_info["info"] = f"HTTP {raw_data.splitlines()[0]}"
                except Exception:
                    pass

        elif UDP in l4_layer:
            packet_info["l4_protocol"] = "UDP"
            packet_info["tag"] = "UDP"
            packet_info["sport"] = l4_layer[UDP].sport
            packet_info["dport"] = l4_layer[UDP].dport
            packet_info["info"] = f"UDP {packet_info['sport']} -> {packet_info['dport']}"

            if (packet_info["sport"] == 53 or packet_info["dport"] == 53) and l4_layer.haslayer(DNS):
                packet_info["tag"] = "DNS"
                dns_layer = l4_layer[DNS]
                if dns_layer.qr == 0 and dns_layer.qdcount > 0 and dns_layer.qd:
                    query_name = dns_layer.qd.qname.decode('utf-8')
                    packet_info["info"] = f"DNS Query: {query_name}"
                elif dns_layer.qr == 1:
                    packet_info["info"] = f"DNS Response"

        elif ICMP in l4_layer:
            packet_info["l4_protocol"] = "ICMP"
            packet_info["tag"] = "ICMP"
            packet_info["icmp_type"] = l4_layer[ICMP].type
            packet_info["icmp_code"] = l4_layer[ICMP].code
            packet_info["info"] = f"ICMP Type {packet_info['icmp_type']}, Code {packet_info['icmp_code']}"
        else:
            packet_info["l4_protocol"] = packet.sprintf("%IP.proto%")
            packet_info["info"] = packet_info["summary"]

        return packet_info

    def update_gui_elements(self, packet_info):
        log_entry = f"[{packet_info['timestamp']}] {packet_info['info']}"
        self.log_message(log_entry)

        values = (
            "",
            packet_info['timestamp'],
            packet_info.get('src_ip', 'N/A'),
            packet_info.get('dst_ip', 'N/A'),
            f"{packet_info.get('l3_protocol', 'N/A')}/{packet_info.get('l4_protocol', 'N/A')}",
            packet_info['length'],
            packet_info['info']
        )
        
        tag_to_apply = packet_info.get("tag", "Other")
        item_id = self.packet_tree.insert("", tk.END, values=values, tags=(tag_to_apply,))
        
        index = len(self.packet_tree.get_children())
        self.packet_tree.set(item_id, "#", index)

    def on_packet_select(self, event):
        selection = self.packet_tree.selection()
        if selection:
            item_id = selection[0]
            try:
                packet_index_str = self.packet_tree.item(item_id, "values")[0]
                packet_index = int(packet_index_str) - 1
                
                if 0 <= packet_index < len(captured_packets):
                    packet = captured_packets[packet_index]
                    
                    f = io.StringIO()
                    with redirect_stdout(f):
                        packet.show()
                    details = f.getvalue()
                    
                    details += "\n\n" + ("-"*20) + " HEX DUMP " + ("-"*20) + "\n\n"
                    f_hex = io.StringIO()
                    with redirect_stdout(f_hex):
                        hexdump(packet)
                    details += f_hex.getvalue()

                    self.details_text.config(state=tk.NORMAL)
                    self.details_text.delete(1.0, tk.END)
                    self.details_text.insert(tk.END, details)
                    self.details_text.config(state=tk.DISABLED)
                else:
                    self.log_message(f"[ERROR] Index mismatch for packet {packet_index_str}")
            
            except Exception as e:
                self.log_message(f"[ERROR] Could not display packet details: {e}")
                print(f"Detail view error: {e}")
    
    def update_stats_timer(self):
        if not stop_sniffing.is_set():
            self.update_stats()
            self.root.after(2000, self.update_stats_timer)

    def update_stats(self):
        global statistics
        
        proto_stats = defaultdict(int)
        src_ips = defaultdict(int)
        dst_ips = defaultdict(int)

        stats_copy = statistics.copy()

        for key, count in stats_copy.items():
            if key.startswith("SRC_"):
                src_ips[key[4:]] = count
            elif key.startswith("DST_"):
                dst_ips[key[4:]] = count
            else:
                proto_stats[key] = count
        
        sorted_src = sorted(src_ips.items(), key=lambda item: item[1], reverse=True)
        sorted_dst = sorted(dst_ips.items(), key=lambda item: item[1], reverse=True)
        
        stats_str = f"--- Overview ---\n"
        stats_str += f"Total Packets Captured: {len(captured_packets)}\n\n"
        
        stats_str += f"--- Protocol Breakdown ---\n"
        if not proto_stats:
            stats_str += "No packets captured.\n"
        for proto, count in sorted(proto_stats.items()):
            stats_str += f"{proto:<10}: {count}\n"
        
        stats_str += f"\n\n--- Top 5 Source IPs ---\n"
        if not sorted_src:
            stats_str += "No IP traffic captured.\n"
        for ip, count in sorted_src[:5]:
            stats_str += f"{ip:<18}: {count} packets\n"
        
        stats_str += f"\n\n--- Top 5 Destination IPs ---\n"
        if not sorted_dst:
            stats_str += "No IP traffic captured.\n"
        for ip, count in sorted_dst[:5]:
            stats_str += f"{ip:<18}: {count} packets\n"

        try:
            self.stats_text.config(state=tk.NORMAL)
            self.stats_text.delete(1.0, tk.END)
            self.stats_text.insert(tk.END, stats_str)
            self.stats_text.config(state=tk.DISABLED)
        except tk.TclError:
            pass

    def save_pcap(self):
        global captured_packets
        if not captured_packets:
            messagebox.showinfo("Info", "No packets captured to save.")
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=".pcap",
            filetypes=[("PCAP Files", "*.pcap"), ("All Files", "*.*")]
        )
        if filename:
            try:
                from scapy.utils import wrpcap
                wrpcap(filename, captured_packets)
                messagebox.showinfo("Success", f"PCAP file saved: {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save PCAP: {e}")

    def save_log(self):
        content = self.log_text.get(1.0, tk.END).strip()
        if not content:
            messagebox.showinfo("Info", "Log is empty.")
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write(content)
                messagebox.showinfo("Success", f"Log file saved: {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save log: {e}")

def main():
    root = tk.Tk()
    app = NetworkSnifferGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
