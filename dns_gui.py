import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from dns_tool import dns_lookup, visualize_response_time, dns_health_check

class DNSApp:
    def __init__(self, root):
        self.root = root
        root.title("DNS Query Tool")
        root.geometry("800x600")

        # Input Fields
        ttk.Label(root, text="Domain:").grid(row=0, column=0, padx=10, pady=10)
        self.domain_entry = ttk.Entry(root, width=30)
        self.domain_entry.grid(row=0, column=1, padx=10, pady=10)

        # Record Type Dropdown
        ttk.Label(root, text="Record Type:").grid(row=1, column=0, padx=10, pady=10)
        self.record_type = ttk.Combobox(root, values=["A", "AAAA", "MX", "TXT", "NS"])
        self.record_type.set("A")
        self.record_type.grid(row=1, column=1, padx=10, pady=10)

        # DNS Server Dropdown
        ttk.Label(root, text="DNS Server:").grid(row=2, column=0, padx=10, pady=10)
        self.dns_server = ttk.Combobox(root, values=["8.8.8.8 (Google)", "1.1.1.1 (Cloudflare)", "208.67.222.222 (OpenDNS)"])
        self.dns_server.set("8.8.8.8 (Google)")
        self.dns_server.grid(row=2, column=1, padx=10, pady=10)

        # Buttons
        ttk.Button(root, text="Lookup", command=self.run_lookup).grid(row=3, column=0, padx=10, pady=10)
        ttk.Button(root, text="Health Check", command=self.run_health_check).grid(row=3, column=1, padx=10, pady=10)
        ttk.Button(root, text="Visualize Speed", command=self.run_visualization).grid(row=3, column=2, padx=10, pady=10)

        # Results Area
        self.results_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=70, height=15)
        self.results_area.grid(row=4, column=0, columnspan=3, padx=10, pady=10)

    def get_server_ip(self):
        server_map = {
            "8.8.8.8 (Google)": "8.8.8.8",
            "1.1.1.1 (Cloudflare)": "1.1.1.1",
            "208.67.222.222 (OpenDNS)": "208.67.222.222"
        }
        return server_map[self.dns_server.get()]

    def run_lookup(self):
        domain = self.domain_entry.get()
        record = self.record_type.get()
        server = self.get_server_ip()
        
        result = dns_lookup(domain, record, server)
        self.results_area.delete(1.0, tk.END)
        self.results_area.insert(tk.INSERT, f"Results for {domain} ({record}):\n{'-'*30}\n{result}")

    def run_health_check(self):
        domain = self.domain_entry.get()
        results = dns_health_check(domain)
        
        self.results_area.delete(1.0, tk.END)
        self.results_area.insert(tk.INSERT, f"Health Check for {domain}:\n{'-'*30}\n")
        for question, status in results.items():
            self.results_area.insert(tk.INSERT, f"{question}: {status}\n")

    def run_visualization(self):
        domain = self.domain_entry.get()
        
        # Create a new window for the plot
        plot_window = tk.Toplevel(self.root)
        plot_window.title("DNS Response Times")
        
        fig = plt.Figure(figsize=(6, 4))
        ax = fig.add_subplot(111)
        
        visualize_response_time(domain)  # Modified to return data instead of showing directly
        canvas = FigureCanvasTkAgg(fig, master=plot_window)
        canvas.draw()
        canvas.get_tk_widget().pack()

if __name__ == "__main__":
    root = tk.Tk()
    app = DNSApp(root)
    root.mainloop()