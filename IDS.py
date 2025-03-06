from scapy.all import sniff
from scapy.layers.inet import IP
import time
import tkinter as tk
from tkinter import messagebox
import socket
import threading


def show_popup(message, title="Network Monitor", msg_type="info"):
    def popup_thread():
        root = tk.Tk()
        root.withdraw()
        if msg_type == "warning":
            messagebox.showwarning(title, message)
        else:
            messagebox.showinfo(title, message)
        root.destroy()

    threading.Thread(target=popup_thread).start()


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        return s.getsockname()[0]
    except Exception:
        return '127.0.0.1'
    finally:
        s.close()


protectedIP = get_local_ip()
attackingIP = None
packet_requests = 0
timeframe_start = time.time()

show_popup(f"Hello! I will now be monitoring your IP address: {protectedIP} for potential attacks!", "Network Detector")


def packet_handler(packet):
    global packet_requests, timeframe_start, attackingIP
    if packet.haslayer(IP) and packet[IP].dst == protectedIP:
        packet_requests += 1
        attackingIP = packet[IP].src
        current_time = time.time()
        time_elapsed = current_time - timeframe_start

        if time_elapsed <= 3:
            if packet_requests >= 1000:
                alert_dos(attackingIP)
                packet_requests = 0
                timeframe_start = current_time
        elif time_elapsed > 3:
            packet_requests = 0
            timeframe_start = current_time


def alert_dos(ip):
    message = (f"Network attack detected from {ip}!\n\n"
               f"To stop it:\n"
               f"1. Contact your network administrator or IT support.\n"
               f"2. Inform your Internet Service Provider (ISP) about the attack.\n"
               f"3. Block the IP {ip} using a firewall if you have access.")
    show_popup(message, "Network Alert", "warning")


def start_sniffing():
    sniff(filter=f"dst host {protectedIP}", prn=packet_handler, store=0)


sniff_thread = threading.Thread(target=start_sniffing)
sniff_thread.daemon = True
sniff_thread.start()


try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    sniff_thread.join()  
