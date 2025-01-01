import tkinter as tk
from tkinter import messagebox, scrolledtext
import socket
import threading

# DNS Resolver function
def resolve_dns():
    target = target_entry.get().strip()
    result_box.delete(1.0, tk.END)
    try:
        ip = socket.gethostbyname(target)
        result_box.insert(tk.END, f"Resolved IP: {ip}\n")
    except socket.gaierror:
        messagebox.showerror("Error", "Invalid domain or IP address!")

# Port Scanner function
def scan_ports():
    target = target_entry.get().strip()
    result_box.delete(1.0, tk.END)
    try:
        ip = socket.gethostbyname(target)
        result_box.insert(tk.END, f"Resolved IP: {ip}\n")
    except socket.gaierror:
        messagebox.showerror("Error", "Invalid domain or IP address!")
        return
    
    def scan_single_port(ip, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                result = s.connect_ex((ip, port))
                if result == 0:
                    result_box.insert(tk.END, f"Port {port}: OPEN\n")
        except Exception:
            pass

    def perform_scan():
        result_box.insert(tk.END, f"Scanning all ports...\n\n")
        for port in range(1, 65536):  # Scanning all ports
            scan_single_port(ip, port)
        result_box.insert(tk.END, "Scanning complete.\n")

    # Run scanning in a separate thread
    threading.Thread(target=perform_scan, daemon=True).start()

# GUI Setup
root = tk.Tk()
root.title("Port Scanner & DNS Resolver")
root.geometry("500x400")

# Input Section
tk.Label(root, text="Enter Target (IP or Domain):").pack(pady=5)
target_entry = tk.Entry(root, width=40)
target_entry.pack(pady=5)

# Buttons
tk.Button(root, text="DNS Resolve", command=resolve_dns, bg="lightblue").pack(pady=5)
tk.Button(root, text="Port Scanner", command=scan_ports, bg="lightgreen").pack(pady=5)

# Result Box
result_box = scrolledtext.ScrolledText(root, wrap=tk.WORD, height=15, width=55)
result_box.pack(pady=10)

# Run the application
root.mainloop()
