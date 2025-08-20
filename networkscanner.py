import tkinter as tk
from tkinter import messagebox, filedialog
from tkinter import ttk
from scapy.all import ARP, Ether, srp  # type: ignore
import socket
import csv
import threading

# === Core Network Scanning Function ===
def scan_network(ip_range):
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=2, verbose=0)[0]

    devices = []
    for sent, received in result:
        ip = received.psrc
        mac = received.hwsrc
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except:
            hostname = "Unknown"
        devices.append({'ip': ip, 'mac': mac, 'hostname': hostname})
    return devices

# === Threaded Scan Handler ===
def start_scan_thread():
    threading.Thread(target=start_scan).start()

def start_scan():
    ip_range = ip_entry.get()
    if not ip_range:
        messagebox.showwarning("Input Error", "Please enter an IP range.")
        return

    for row in tree.get_children():
        tree.delete(row)

    progress_var.set(20)
    window.update()

    devices = scan_network(ip_range)

    progress_var.set(70)
    window.update()

    if not devices:
        messagebox.showinfo("Scan Complete", "No active devices found.")
        progress_var.set(100)
        return

    for device in devices:
        tree.insert('', 'end', values=(device['ip'], device['mac'], device['hostname']))

    global scanned_devices
    scanned_devices = devices
    export_button.config(state=tk.NORMAL)

    progress_var.set(100)

# === Export to CSV ===
def export_to_csv():
    if not scanned_devices:
        messagebox.showinfo("Info", "No data to export.")
        return

    file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
    if not file_path:
        return

    try:
        with open(file_path, mode='w', newline='') as file:
            writer = csv.DictWriter(file, fieldnames=['ip', 'mac', 'hostname'])
            writer.writeheader()
            writer.writerows(scanned_devices)
        messagebox.showinfo("Exported", f"Results saved to {file_path}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

# === GUI Setup ===
window = tk.Tk()
window.title("Python Network Scanner")
window.geometry("700x500")
window.configure(bg="#1e1e2f")

style = ttk.Style()
style.theme_use("clam")
style.configure("TLabel", background="#1e1e2f", foreground="white", font=("Segoe UI", 10))
style.configure("TEntry", padding=5)
style.configure("TButton", font=("Segoe UI", 10), padding=6)
style.configure("Treeview", background="#2e2e3f", foreground="white", fieldbackground="#2e2e3f", font=("Segoe UI", 10))
style.map("Treeview", background=[("selected", "#4444aa")])

# === Layout ===
frame_top = ttk.Frame(window, padding=10)
frame_top.pack(pady=10)

label = ttk.Label(frame_top, text="Enter IP Range (e.g., 192.168.1.0/24):")
label.grid(row=0, column=0, sticky="w")

ip_entry = ttk.Entry(frame_top, width=40)
ip_entry.grid(row=1, column=0, padx=5, pady=5)

scan_button = ttk.Button(frame_top, text="Scan", command=start_scan_thread)
scan_button.grid(row=1, column=1, padx=10)

progress_var = tk.IntVar()
progress_bar = ttk.Progressbar(window, variable=progress_var, maximum=100, length=600)
progress_bar.pack(pady=10)

# Treeview for output
tree = ttk.Treeview(window, columns=("IP", "MAC", "Hostname"), show="headings", height=10)
tree.heading("IP", text="IP Address")
tree.heading("MAC", text="MAC Address")
tree.heading("Hostname", text="Hostname")
tree.column("IP", width=150)
tree.column("MAC", width=180)
tree.column("Hostname", width=250)
tree.pack(padx=10, pady=10)

# Export Button
export_button = ttk.Button(window, text="Export to CSV", command=export_to_csv, state=tk.DISABLED)
export_button.pack(pady=10)

scanned_devices = []

window.mainloop()
