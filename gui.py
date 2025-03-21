import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import dns.resolver
import dns.exception
import time
import threading
from collections import defaultdict

class DNSQueryTool:
    def __init__(self, root):
        self.root = root
        self.root.title("DNS Query Tool")
        self.root.geometry("900x700")
        self.root.minsize(900, 700)

        # DNS Providers with an option for a custom DNS server.
        self.dns_providers = {
            "Google": "8.8.8.8",
            "Cloudflare": "1.1.1.1",
            "OpenDNS": "208.67.222.222",
            "Custom": ""
        }
        
        # Supported DNS record types.
        self.record_types = ["A", "AAAA", "MX", "TXT", "CNAME", "NS", "SOA", "PTR", "SRV"]
        
        # Dictionary to store query results for visualization.
        self.query_results = defaultdict(dict)
        
        # Initialize UI components.
        self.create_ui()

    def create_ui(self):
        # Create notebook tabs.
        self.notebook = ttk.Notebook(self.root)
        
        # Tab for DNS queries.
        self.query_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.query_frame, text="DNS Query")
        
        # Tab for response time visualization.
        self.viz_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.viz_frame, text="Response Time Visualization")
        
        # Tab for mail configuration health checks.
        self.health_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.health_frame, text="Mail Health Check")
        
        self.notebook.pack(expand=True, fill="both", padx=10, pady=10)
        
        # Set up UI in each tab.
        self.setup_query_tab()
        self.setup_viz_tab()
        self.setup_health_tab()

    def setup_query_tab(self):
        # Domain settings.
        frame1 = ttk.LabelFrame(self.query_frame, text="Domain Settings")
        frame1.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(frame1, text="Domain:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.domain_var = tk.StringVar()
        ttk.Entry(frame1, textvariable=self.domain_var, width=40).grid(row=0, column=1, padx=5, pady=5, sticky="w")
        
        # Record type selection.
        ttk.Label(frame1, text="Record Type:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.record_type_var = tk.StringVar(value=self.record_types[0])
        ttk.Combobox(frame1, textvariable=self.record_type_var, values=self.record_types, width=10).grid(row=1, column=1, padx=5, pady=5, sticky="w")
        
        # DNS provider selection.
        frame2 = ttk.LabelFrame(self.query_frame, text="DNS Provider")
        frame2.pack(fill="x", padx=10, pady=5)
        
        self.provider_var = tk.StringVar(value="Google")
        row = 0
        for name in self.dns_providers:
            ttk.Radiobutton(frame2, text=name, variable=self.provider_var, value=name, command=self.toggle_custom_dns).grid(row=row, column=0, padx=5, pady=2, sticky="w")
            row += 1
        
        ttk.Label(frame2, text="Custom DNS:").grid(row=row, column=0, padx=5, pady=5, sticky="w")
        self.custom_dns_var = tk.StringVar()
        self.custom_dns_entry = ttk.Entry(frame2, textvariable=self.custom_dns_var, width=20, state="disabled")
        self.custom_dns_entry.grid(row=row, column=1, padx=5, pady=5, sticky="w")
        
        # Action buttons.
        button_frame = ttk.Frame(self.query_frame)
        button_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Button(button_frame, text="Perform DNS Query", command=self.perform_dns_query).pack(side="left", padx=5, pady=5)
        ttk.Button(button_frame, text="Clear Results", command=self.clear_query_results).pack(side="left", padx=5, pady=5)
        
        # Results display.
        result_frame = ttk.LabelFrame(self.query_frame, text="Query Results")
        result_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.result_text = scrolledtext.ScrolledText(result_frame, wrap=tk.WORD, width=80, height=20)
        self.result_text.pack(fill="both", expand=True, padx=5, pady=5)

    def setup_viz_tab(self):
        # Controls for response time comparison.
        control_frame = ttk.LabelFrame(self.viz_frame, text="Visualization Controls")
        control_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(control_frame, text="Domain:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.viz_domain_var = tk.StringVar()
        ttk.Entry(control_frame, textvariable=self.viz_domain_var, width=40).grid(row=0, column=1, padx=5, pady=5, sticky="w")
        
        ttk.Label(control_frame, text="Record Type:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.viz_record_type_var = tk.StringVar(value=self.record_types[0])
        ttk.Combobox(control_frame, textvariable=self.viz_record_type_var, values=self.record_types, width=10).grid(row=1, column=1, padx=5, pady=5, sticky="w")
        
        ttk.Label(control_frame, text="Number of Queries:").grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.num_queries_var = tk.IntVar(value=5)
        ttk.Spinbox(control_frame, from_=1, to=20, textvariable=self.num_queries_var, width=5).grid(row=2, column=1, padx=5, pady=5, sticky="w")
        
        # Provider selection checkboxes.
        provider_frame = ttk.LabelFrame(control_frame, text="Select Providers to Compare")
        provider_frame.grid(row=3, column=0, columnspan=2, padx=5, pady=5, sticky="we")
        
        self.provider_vars = {}
        col = 0
        for provider in list(self.dns_providers.keys())[:-1]:  # Exclude custom DNS for comparison.
            self.provider_vars[provider] = tk.BooleanVar(value=True)
            ttk.Checkbutton(provider_frame, text=provider, variable=self.provider_vars[provider]).grid(row=0, column=col, padx=10, pady=5, sticky="w")
            col += 1
        
        # Button to start comparison.
        ttk.Button(control_frame, text="Run Comparison", command=self.run_response_time_comparison).grid(row=4, column=0, columnspan=2, padx=5, pady=10)
        
        # Plot area for visualization.
        plot_frame = ttk.LabelFrame(self.viz_frame, text="Response Time Comparison")
        plot_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.fig, self.ax = plt.subplots(figsize=(8, 4), tight_layout=True)
        self.canvas = FigureCanvasTkAgg(self.fig, master=plot_frame)
        self.canvas.get_tk_widget().pack(fill="both", expand=True)

    def setup_health_tab(self):
        # Domain settings for health checks.
        frame = ttk.LabelFrame(self.health_frame, text="Domain Settings")
        frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(frame, text="Domain:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.health_domain_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.health_domain_var, width=40).grid(row=0, column=1, padx=5, pady=5, sticky="w")
        
        # Options for mail health checks.
        check_frame = ttk.LabelFrame(self.health_frame, text="Health Checks")
        check_frame.pack(fill="x", padx=10, pady=5)
        
        self.check_spf_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(check_frame, text="Validate SPF Records", variable=self.check_spf_var).grid(row=0, column=0, padx=5, pady=5, sticky="w")
        
        self.check_dmarc_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(check_frame, text="Validate DMARC Records", variable=self.check_dmarc_var).grid(row=0, column=1, padx=5, pady=5, sticky="w")
        
        self.check_mx_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(check_frame, text="Validate MX Configuration", variable=self.check_mx_var).grid(row=1, column=0, padx=5, pady=5, sticky="w")
        
        ttk.Button(check_frame, text="Run Health Check", command=self.run_health_check).grid(row=2, column=0, columnspan=2, padx=5, pady=10)
        
        # Results display for health checks.
        result_frame = ttk.LabelFrame(self.health_frame, text="Health Check Results")
        result_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.health_result_text = scrolledtext.ScrolledText(result_frame, wrap=tk.WORD, width=80, height=20)
        self.health_result_text.pack(fill="both", expand=True, padx=5, pady=5)

    def toggle_custom_dns(self):
        if self.provider_var.get() == "Custom":
            self.custom_dns_entry.config(state="normal")
        else:
            self.custom_dns_entry.config(state="disabled")

    def perform_dns_query(self):
        domain = self.domain_var.get().strip()
        record_type = self.record_type_var.get()
        provider = self.provider_var.get()
        
        if not domain:
            messagebox.showerror("Error", "Please enter a domain name")
            return
        
        # Determine DNS server.
        if provider == "Custom":
            dns_server = self.custom_dns_var.get().strip()
            if not dns_server:
                messagebox.showerror("Error", "Please enter a custom DNS server IP address")
                return
        else:
            dns_server = self.dns_providers[provider]
        
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, f"Querying {domain} for {record_type} records using {provider} DNS ({dns_server})...\n\n")
        self.root.update()
        
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [dns_server]
        
        try:
            start_time = time.time()
            answers = resolver.resolve(domain, record_type)
            elapsed_time = time.time() - start_time
            
            # Save response time for later visualization.
            if domain not in self.query_results:
                self.query_results[domain] = {}
            if record_type not in self.query_results[domain]:
                self.query_results[domain][record_type] = {}
            self.query_results[domain][record_type][provider] = elapsed_time
            
            self.result_text.insert(tk.END, f"Query completed in {elapsed_time:.4f} seconds\n\n")
            self.result_text.insert(tk.END, f"Results for {domain} ({record_type} records):\n")
            self.result_text.insert(tk.END, "-" * 50 + "\n")
            
            for rdata in answers:
                if record_type == "MX":
                    self.result_text.insert(tk.END, f"Priority: {rdata.preference}, Server: {rdata.exchange}\n")
                elif record_type == "TXT":
                    txt = b" ".join(rdata.strings).decode("utf-8", errors="ignore")
                    self.result_text.insert(tk.END, f"Text: {txt}\n")
                else:
                    self.result_text.insert(tk.END, f"{rdata}\n")
                    
        except dns.exception.DNSException as e:
            self.result_text.insert(tk.END, f"Error: {str(e)}\n")

    def clear_query_results(self):
        self.result_text.delete(1.0, tk.END)

    def run_response_time_comparison(self):
        domain = self.viz_domain_var.get().strip()
        record_type = self.viz_record_type_var.get()
        num_queries = self.num_queries_var.get()
        
        if not domain:
            messagebox.showerror("Error", "Please enter a domain name")
            return
        
        selected_providers = [provider for provider, var in self.provider_vars.items() if var.get()]
        if not selected_providers:
            messagebox.showerror("Error", "Please select at least one DNS provider")
            return
        
        # Create a progress window.
        progress_window = tk.Toplevel(self.root)
        progress_window.title("Running Comparison")
        progress_window.geometry("300x150")
        progress_window.transient(self.root)
        progress_window.grab_set()
        
        ttk.Label(progress_window, text="Running DNS query comparison...").pack(pady=10)
        progress = ttk.Progressbar(progress_window, orient="horizontal", length=250, mode="determinate")
        progress.pack(pady=10, padx=20)
        status_label = ttk.Label(progress_window, text="Starting...")
        status_label.pack(pady=10)
        
        def run_comparison():
            results = {provider: [] for provider in selected_providers}
            total_ops = len(selected_providers) * num_queries
            completed = 0
            
            for provider in selected_providers:
                dns_server = self.dns_providers[provider]
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [dns_server]
                
                for i in range(num_queries):
                    try:
                        status_label.config(text=f"Querying {provider} ({i+1}/{num_queries})")
                        start_time = time.time()
                        resolver.resolve(domain, record_type)
                        elapsed_time = time.time() - start_time
                        results[provider].append(elapsed_time * 1000)  # Convert to milliseconds.
                    except dns.exception.DNSException:
                        results[provider].append(None)
                    
                    completed += 1
                    progress["value"] = (completed / total_ops) * 100
                    self.root.update()
            
            self.plot_response_times(domain, record_type, results)
            progress_window.destroy()
        
        threading.Thread(target=run_comparison, daemon=True).start()

    def plot_response_times(self, domain, record_type, results):
        self.ax.clear()
        
        # Compute the average response time for each provider.
        means = {}
        for provider, times in results.items():
            valid_times = [t for t in times if t is not None]
            if valid_times:
                means[provider] = sum(valid_times) / len(valid_times)
        
        positions = range(len(means))
        providers = list(means.keys())
        response_times = [means[provider] for provider in providers]
        
        bars = self.ax.bar(positions, response_times)
        
        self.ax.set_title(f"DNS Response Time for {domain} ({record_type})")
        self.ax.set_xlabel("DNS Provider")
        self.ax.set_ylabel("Response Time (ms)")
        self.ax.set_xticks(positions)
        self.ax.set_xticklabels(providers)
        
        # Annotate bars with response times.
        for bar, resp_time in zip(bars, response_times):
            height = bar.get_height()
            self.ax.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                         f"{resp_time:.2f} ms", ha='center', va='bottom', rotation=0)
        
        self.canvas.draw()

    def run_health_check(self):
        domain = self.health_domain_var.get().strip()
        
        if not domain:
            messagebox.showerror("Error", "Please enter a domain name")
            return
        
        self.health_result_text.delete(1.0, tk.END)
        self.health_result_text.insert(tk.END, f"Running health checks for {domain}...\n\n")
        self.root.update()
        
        # Use Google's DNS for consistency.
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [self.dns_providers["Google"]]
        
        checks_passed = 0
        checks_failed = 0
        
        # SPF record check.
        if self.check_spf_var.get():
            self.health_result_text.insert(tk.END, "=== SPF RECORD CHECK ===\n")
            try:
                answers = resolver.resolve(domain, "TXT")
                spf_found = False
                
                for rdata in answers:
                    txt = b" ".join(rdata.strings).decode("utf-8", errors="ignore")
                    if txt.startswith("v=spf1"):
                        spf_found = True
                        self.health_result_text.insert(tk.END, f"✓ SPF record found: {txt}\n")
                        if "all" not in txt:
                            self.health_result_text.insert(tk.END, "⚠ Warning: SPF record does not contain an 'all' mechanism\n")
                        checks_passed += 1
                        break
                
                if not spf_found:
                    self.health_result_text.insert(tk.END, "✗ No SPF record found\n")
                    checks_failed += 1
            except dns.exception.DNSException as e:
                self.health_result_text.insert(tk.END, f"✗ Error checking SPF: {str(e)}\n")
                checks_failed += 1
            
            self.health_result_text.insert(tk.END, "\n")
        
        # DMARC record check.
        if self.check_dmarc_var.get():
            self.health_result_text.insert(tk.END, "=== DMARC RECORD CHECK ===\n")
            try:
                dmarc_domain = f"_dmarc.{domain}"
                try:
                    answers = resolver.resolve(dmarc_domain, "TXT")
                    dmarc_found = False
                    
                    for rdata in answers:
                        txt = b" ".join(rdata.strings).decode("utf-8", errors="ignore")
                        if txt.startswith("v=DMARC1"):
                            dmarc_found = True
                            self.health_result_text.insert(tk.END, f"✓ DMARC record found: {txt}\n")
                            if "p=none" in txt:
                                self.health_result_text.insert(tk.END, "⚠ Warning: DMARC policy is set to 'none' (monitoring only)\n")
                            checks_passed += 1
                            break
                    
                    if not dmarc_found:
                        self.health_result_text.insert(tk.END, f"✗ No DMARC record found at {dmarc_domain}\n")
                        checks_failed += 1
                except dns.exception.DNSException:
                    self.health_result_text.insert(tk.END, f"✗ No DMARC record found at {dmarc_domain}\n")
                    checks_failed += 1
            except Exception as e:
                self.health_result_text.insert(tk.END, f"✗ Error checking DMARC: {str(e)}\n")
                checks_failed += 1
            
            self.health_result_text.insert(tk.END, "\n")
        
        # MX record check.
        if self.check_mx_var.get():
            self.health_result_text.insert(tk.END, "=== MX RECORD CHECK ===\n")
            try:
                answers = resolver.resolve(domain, "MX")
                
                if answers:
                    self.health_result_text.insert(tk.END, "✓ MX records found:\n")
                    for rdata in answers:
                        self.health_result_text.insert(tk.END, f"  - Priority: {rdata.preference}, Server: {rdata.exchange}\n")
                    
                    self.health_result_text.insert(tk.END, "\nMail Server Validation:\n")
                    all_ok = True
                    
                    for rdata in answers:
                        mx_host = str(rdata.exchange).rstrip(".")
                        try:
                            resolver.resolve(mx_host, "A")
                            self.health_result_text.insert(tk.END, f"✓ {mx_host} resolves to a valid IP address\n")
                        except dns.exception.DNSException:
                            self.health_result_text.insert(tk.END, f"✗ {mx_host} does not resolve to a valid IP address\n")
                            all_ok = False
                    
                    if all_ok:
                        checks_passed += 1
                    else:
                        checks_failed += 1
                else:
                    self.health_result_text.insert(tk.END, "✗ No MX records found\n")
                    checks_failed += 1
            except dns.exception.DNSException as e:
                self.health_result_text.insert(tk.END, f"✗ Error checking MX records: {str(e)}\n")
                checks_failed += 1
            
            self.health_result_text.insert(tk.END, "\n")
        
        # Summary of health checks.
        self.health_result_text.insert(tk.END, "=== SUMMARY ===\n")
        total_checks = checks_passed + checks_failed
        if total_checks > 0:
            pass_percent = (checks_passed / total_checks) * 100
            self.health_result_text.insert(tk.END, f"Checks passed: {checks_passed}/{total_checks} ({pass_percent:.1f}%)\n")
            if checks_failed == 0:
                self.health_result_text.insert(tk.END, "✅ All checks passed!\n")
            else:
                self.health_result_text.insert(tk.END, f"⚠ {checks_failed} check(s) failed. See details above.\n")
        else:
            self.health_result_text.insert(tk.END, "No checks were performed.\n")
