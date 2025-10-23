# CodeAlpha-Basic-Network-Sniffer

A powerful network packet sniffer with an intuitive GUI built using Python, Tkinter, and Scapy. Features real-time packet capture, deep packet inspection, protocol analysis, and comprehensive statistics.


## ✨ Features

- 🖥️ **User-Friendly GUI** - Clean interface built with Tkinter
- 📦 **Deep Packet Inspection** - Detailed analysis of network packets
- 🎨 **Color-Coded Protocols** - Visual distinction between TCP, UDP, ICMP, ARP, DNS, and HTTP
- 📊 **Live Statistics** - Real-time protocol breakdown and top talkers
- 💾 **Export Capabilities** - Save captures as PCAP files or text logs
- 🔍 **BPF Filtering** - Apply Berkeley Packet Filters for targeted capture
- 🔐 **Hex Dump Viewer** - Low-level packet inspection
- 📈 **Multi-Tab Interface** - Organized view of logs, packets, details, and statistics

## 📋 Requirements

- Python 3.7 or higher
- Administrator/Root privileges (required for packet capture)

## 🚀 Installation

### 1. Clone the repository
```bash
git clone https://github.com/mrbugsniffer/codealpha_tasks
cd codealpha_tasks
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Run the application
```bash
# On Linux/macOS (requires sudo)
sudo python3 src/main.py

# On Windows (run as Administrator)
python src/main.py
```

## 📖 Usage

### Basic Usage
1. Select a network interface from the dropdown
2. (Optional) Enter a BPF filter (e.g., `tcp port 80`)
3. Click "Start Sniffing" to begin capture
4. View packets in real-time across different tabs
5. Click "Stop Sniffing" when done

### BPF Filter Examples
