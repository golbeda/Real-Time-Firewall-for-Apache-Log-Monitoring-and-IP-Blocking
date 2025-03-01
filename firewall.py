import threading
import os
import time
import tkinter as tk
from tkinter import messagebox
from urllib.parse import urlparse
from os.path import splitext

# Configurations
MAX_REQUESTS = 3
LOG_FILE = "/var/log/apache2/access.log"
WHITE_LIST = ["127.0.0.1"]
WHITE_EXTS = [".ico", ".pdf", ".flv", ".jpg", ".jpeg", ".png", ".gif", ".js", ".css", ".swf", ".xml", ".txt", ".htm", ".html"]

# Firewall Data
blocked_ips = set()
request_counts = {}
running = False

# Function to check if an IP is blocked
def is_ip_blocked(ip):
    result = os.popen(f"iptables -L INPUT -v -n | grep '{ip}'").read()
    return bool(result)

# Function to extract file extension from a URL
def get_ext(url):
    parsed = urlparse(url)
    root, ext = splitext(parsed.path)
    return ext

# Function to block an IP
def block_ip(ip):
    if ip not in WHITE_LIST and not is_ip_blocked(ip):
        os.system(f"iptables -A INPUT -s {ip} -j DROP")
        blocked_ips.add(ip)
        update_listbox()

        # Notify GUI
        root.after(0, messagebox.showinfo, "Firewall", f"Blocked IP: {ip}")

# Function to manually block an IP from GUI
def manual_block():
    ip = ip_entry.get().strip()
    if ip:
        block_ip(ip)
        ip_entry.delete(0, tk.END)

# Function to unblock an IP
def unblock_ip():
    selected = listbox.curselection()
    if selected:
        ip = listbox.get(selected[0])
        os.system(f"iptables -D INPUT -s {ip} -j DROP")
        blocked_ips.discard(ip)
        update_listbox()

        root.after(0, messagebox.showinfo, "Firewall", f"Unblocked IP: {ip}")

# Function to continuously monitor Apache logs
def monitor_logs():
    global running
    running = True

    try:
        with open(LOG_FILE, 'r') as infile:
            infile.seek(0, os.SEEK_END)  # Move to end of file to read new logs
            
            while running:
                line = infile.readline()
                if not line:
                    time.sleep(1)  # Wait for new log lines
                    continue

                frags = line.split(' ', 8)
                if len(frags) < 7:
                    continue

                ip = frags[0]
                request_time = frags[3]
                url_requested = frags[6]

                # Update GUI with log entry
                log_entry = f"{ip} requested {url_requested} at {request_time}"
                root.after(0, log_listbox.insert, tk.END, log_entry)

                # Check if request should be blocked
                if get_ext(url_requested) not in WHITE_EXTS:
                    if ip in request_counts:
                        request_counts[ip] += 1
                    else:
                        request_counts[ip] = 1

                    if request_counts[ip] >= MAX_REQUESTS:
                        block_ip(ip)

    except Exception as e:
        root.after(0, messagebox.showerror, "Error", f"Failed to read logs: {e}")

# Function to start monitoring logs in a separate thread
def start_firewall():
    if not running:
        threading.Thread(target=monitor_logs, daemon=True).start()
        root.after(0, messagebox.showinfo, "Firewall", "Monitoring started!")

# Function to stop monitoring
def stop_firewall():
    global running
    running = False
    root.after(0, messagebox.showinfo, "Firewall", "Monitoring stopped!")

# Function to update the blocked IP listbox
def update_listbox():
    listbox.delete(0, tk.END)
    for ip in blocked_ips:
        listbox.insert(tk.END, ip)

# GUI Setup
root = tk.Tk()
root.title("Firewall Protection")
root.geometry("500x500")

frame = tk.Frame(root)
frame.pack(pady=10)

# Log display
tk.Label(frame, text="Access Logs:").pack()
log_listbox = tk.Listbox(frame, width=60, height=10)
log_listbox.pack()

# Blocked IPs
tk.Label(frame, text="Blocked IPs:").pack()
listbox = tk.Listbox(frame, width=40, height=5)
listbox.pack()

btn_frame = tk.Frame(root)
btn_frame.pack(pady=10)

# Control buttons
tk.Button(btn_frame, text="Start Firewall", command=start_firewall).grid(row=0, column=0, padx=5, pady=5)
tk.Button(btn_frame, text="Stop Firewall", command=stop_firewall).grid(row=0, column=1, padx=5, pady=5)
tk.Button(btn_frame, text="Unblock IP", command=unblock_ip).grid(row=1, column=0, columnspan=2, padx=5, pady=5)

# Manual IP blocking
tk.Label(root, text="Enter IP to Block:").pack()
ip_entry = tk.Entry(root, width=20)
ip_entry.pack()
tk.Button(root, text="Block IP", command=manual_block).pack(pady=5)

root.mainloop()
