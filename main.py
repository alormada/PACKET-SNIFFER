import tkinter as tk
from tkinter import scrolledtext, Listbox, messagebox
import threading
from scapy.layers.l2 import ARP, Ether, srp
from scapy.all import sniff
import netifaces
import requests

class PacketSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer")
        self.root.geometry("1080x800")
        self.packet_counts = {}

        self.packet_count_label = tk.Label(root, text="Packets Sent/Received: 0/0", font=("Helvetica", 12))
        self.packet_count_label.pack(pady=5)

        self.listbox_title_label = tk.Label(root, text="Discovered Devices", font=("Helvetica", 12, "bold"))
        self.listbox_title_label.pack(pady=5)

        self.device_listbox = Listbox(root, selectmode=tk.SINGLE, width=100, height=10)
        self.device_listbox.pack(pady=10)
        self.device_listbox.bind('<ButtonRelease-1>', self.show_device_info)

        self.refresh_button = tk.Button(root, text="Refresh", command=self.auto_search_devices)
        self.refresh_button.pack(pady=5)

        self.scrollText_title_label = tk.Label(root, font=("Helvetica", 12, "bold"))
        self.scrollText_title_label.pack(pady=5)

        self.info_text = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=100, height=10)
        self.info_text.pack(pady=10)

        self.start_button = tk.Button(root, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack(pady=5)

        self.stop_button = tk.Button(root, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.pack(pady=5)

        self.packet_counts = {}
        self.local_address = None
        self.mask = None
        self.ip_range = None
        self.devices = []
        self.selected_device_info = None

        self.stop_sniffing_flag = False

        self.packet_counter = 0

        # Automatically search for devices when the program starts
        self.auto_search_devices()

    def auto_search_devices(self):
        self.stop_sniffing()
        self.device_listbox.delete(0, tk.END)
        self.info_text.delete(1.0, tk.END)
        # Automatically search for devices
        self.local_address = self.get_local_ip_and_mask()
        if self.local_address:
            self.info_text.insert(tk.END, str(self.local_address) + "\n")
            self.mask = self.subnet_mask_to_cidr(self.local_address[1])
            self.ip_range = self.local_address[0] + self.mask
            self.info_text.insert(tk.END, self.ip_range + "\n")
            self.devices = self.discover_devices(self.ip_range)

            if self.devices:
                for device in self.devices:
                    self.device_listbox.insert(tk.END, f"IP: {device['ip']}, MAC: {device['mac']}, Manufacturer: {device['manufacturer']}")
            else:
                self.info_text.insert(tk.END, "No devices found.\n")

    def get_local_ip_and_mask(self):
        # Getting a list of all network interfaces on your device
        interfaces = netifaces.interfaces()
        # For every interface on your device
        for interface in interfaces:
            # Get information about addresses on your interface
            addresses = netifaces.ifaddresses(interface)

            # Check if there is information about IPv4 address on the current interface
            if netifaces.AF_INET in addresses:
                # Get information about the first IPv4 address
                info_ipv4 = addresses[netifaces.AF_INET][0]

                # Get the IPv4 address
                ip_address = info_ipv4['addr']

                # Get subnet mask (if available, else None)
                subnet_mask = info_ipv4.get('netmask', None)

                mac_address = addresses[netifaces.AF_LINK][0]['addr']

                # If both IP address and subnet mask are available, print and return them
                if ip_address and subnet_mask:
                    if ip_address.startswith("192.168.") or ip_address.startswith("172") or ip_address.startswith("10"):
                        return [ip_address, subnet_mask, mac_address]

    # Format subnet mask into cidr notation
    def subnet_mask_to_cidr(self, subnet_mask_str):
        subnet_mask_parts = list(map(int, subnet_mask_str.split('.')))
        binary_subnet_mask = ''.join(format(part, '08b') for part in subnet_mask_parts)
        prefix_length = binary_subnet_mask.count('1')
        cidr_notation = f"/{prefix_length}"
        return cidr_notation

    # Get name of the device manufacturer
    def get_device_manufacturer(self, mac_address):
        try:
            response = requests.get(f"https://api.macvendors.com/{mac_address}")
            if response.status_code == 200:
                return response.text
            else:
                return "Unknown"
        except requests.RequestException:
            return "Request error"

    # Sent ARP request
    def discover_devices(self, ip_range):
        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
        result = srp(arp_request, timeout=3, verbose=0)[0]
        devices = []
        ip_add = self.get_local_ip_and_mask()[0]
        mac_add = self.get_local_ip_and_mask()[2]
        manufacturer = self.get_device_manufacturer(mac_add)
        devices.append({'ip': ip_add, 'mac': mac_add, 'manufacturer': manufacturer})

        for sent, received in result:
            # Check if the device already exists in list
            if received.hwsrc != mac_add:
                manufacturer = self.get_device_manufacturer(received.hwsrc)
                devices.append({'ip': received.psrc, 'mac': received.hwsrc, 'manufacturer': manufacturer})

        return devices

    def show_device_info(self, event):
        self.stop_sniffing()
        selected_index = self.device_listbox.curselection()
        if selected_index:
            selected_device = self.devices[selected_index[0]]
            info = f"IP: {selected_device['ip']}\nMAC: {selected_device['mac']}\nManufacturer: {selected_device['manufacturer']}"
            self.info_text.delete(1.0, tk.END)
            self.info_text.insert(tk.END, info)
            self.selected_device_info = selected_device
            self.scrollText_title_label.config(text=f"Information for {selected_device['ip']}")
            packet_counts = self.packet_counts.get(selected_device['ip'], {'sent': 0, 'received': 0})
            self.packet_count_label.config(text=f"Packets Sent/Received: {packet_counts['sent']}/{packet_counts['received']}")
        else:
            messagebox.showinfo("No Device Selected", "Please select a device from the list.")

    def start_sniffing(self):
        self.local_address = self.get_local_ip_and_mask()
        self.mask = self.subnet_mask_to_cidr(self.local_address[1])
        self.ip_range = self.local_address[0] + self.mask
        self.info_text.insert(tk.END, "\n\nPacket Sniffing Started...\n")
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.stop_sniffing_flag = False
        threading.Thread(target=self.sniff_packets).start()

    def stop_sniffing(self):

        self.info_text.insert(tk.END, "Packet Sniffing Stopping...\n")
        self.stop_sniffing_flag = True
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def sniff_packets(self):
        timeout = 1  # seconds
        packets = sniff(prn=self.packet_callback, timeout=timeout, store=0)
        while not self.stop_sniffing_flag and not packets:
            packets = sniff(prn=self.packet_callback, timeout=timeout, store=0)

        if not self.stop_sniffing_flag:
            self.info_text.insert(tk.END, "Packet Sniffing Stopped.\n")
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)

    # Show packets information
    def packet_callback(self, packet):
        if self.stop_sniffing_flag or self.selected_device_info is None:
            return

        if packet.haslayer('IP'):
            ip_layer = packet.getlayer('IP')
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            selected_ip = self.selected_device_info['ip']

            if src_ip == selected_ip or dst_ip == selected_ip:
                self.packet_counter += 1
                if src_ip == selected_ip:
                    self.packet_counts.setdefault(src_ip, {'sent': 0, 'received': 0})
                    self.packet_counts[src_ip]['sent'] += 1
                if dst_ip == selected_ip:
                    self.packet_counts.setdefault(dst_ip, {'sent': 0, 'received': 0})
                    self.packet_counts[dst_ip]['received'] += 1

                packet_counts = self.packet_counts[selected_ip]
                self.packet_count_label.config(
                    text=f"Packets Sent/Received: {packet_counts['sent']}/{packet_counts['received']}")

                packet_summary = packet.summary()
                self.info_text.insert(tk.END, packet_summary + "\n")
                self.info_text.yview(tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()
