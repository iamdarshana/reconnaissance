import dns.resolver
import whois
import requests
from duckduckgo_search import DDGS
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.theme import Theme
import json
from abc import ABC, abstractmethod
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
from datetime import datetime

custom_theme = Theme({
    "title": "bold magenta",
    "header": "bold pink1",
    "info": "pink1",
    "success": "bright_magenta",
    "error": "bold red"
})
console = Console(theme=custom_theme)

class Target:
    def __init__(self, domain, ipaddress=None, metadata=None):
        self.domain = domain
        self._ipaddress = ipaddress
        self.__metadata = metadata

    def resolve_domain(self):
        try:
            answers = dns.resolver.resolve(self.domain, "A")
            self._ipaddress = [str(ans) for ans in answers]
            return self._ipaddress
        except Exception:
            return None

    def _store_metadata(self):
        return {"domain": self.domain, "ip": self._ipaddress, "metadata": self.__metadata}

    def __sanitize(self):
        return self.domain.strip().lower()

class ReconModule(ABC):
    def __init__(self, module_name):
        self.module_name = module_name

    @abstractmethod
    def run(self): pass

    @abstractmethod
    def get_output(self): pass

    @abstractmethod
    def _log_result(self): pass

class DNSRecon(ReconModule):
    def __init__(self, module_name, target):
        super().__init__(module_name)
        self.target = target
        self.__results = {}

    def run(self):
        record_types = ["A", "AAAA", "MX", "NS", "TXT"]
        for rtype in record_types:
            records = self._query_dns_records(rtype)
            if records:
                self.__results[rtype] = records
        self._log_result()

    def _query_dns_records(self, rtype):
        try:
            answers = dns.resolver.resolve(self.target.domain, rtype)
            return [str(ans) for ans in answers]
        except Exception:
            return None

    def get_output(self):
        return self.__results

    def _log_result(self):
        table = Table(title=f"DNS Records for {self.target.domain}", style="header")
        table.add_column("Type", style="title")
        table.add_column("Values", style="info")
        for rtype, values in self.__results.items():
            table.add_row(rtype, ", ".join(values))
        console.print(table)

class WhoisRecon(ReconModule):
    def __init__(self, module_name, target):
        super().__init__(module_name)
        self.target = target
        self._raw_data = None
        self.__clean_output = {}

    def run(self):
        try:
            self._raw_data = whois.whois(self.target.domain)
            self.__process_whois()
            self._log_result()
        except Exception as e:
            self.__clean_output = {"error": str(e)}

    def __process_whois(self):
        try:
            self.__clean_output = {
                "Domain Name": getattr(self._raw_data, "domain_name", None),
                "Registrar": getattr(self._raw_data, "registrar", None),
                "Creation Date": str(getattr(self._raw_data, "creation_date", "")),
                "Expiration Date": str(getattr(self._raw_data, "expiration_date", "")),
                "Emails": getattr(self._raw_data, "emails", []),
                "Name Servers": getattr(self._raw_data, "name_servers", [])
            }
        except Exception as e:
            self.__clean_output = {"error": str(e)}

    def get_output(self):
        return self.__clean_output

    def _log_result(self):
        panel = Panel.fit(
            json.dumps(self.__clean_output, indent=4),
            title=f"WHOIS Data for {self.target.domain}",
            style="success"
        )
        console.print(panel)

class SubdomainFinder(ReconModule):
    def __init__(self, module_name, target):
        super().__init__(module_name)
        self.target = target
        self.found_subdomains = []

    def run(self):
        crt_results = self._enumerate_crtsh()
        brute_results = self._bruteforce_subdomains()
        candidates = set(crt_results + brute_results)
        for sub in candidates:
            if self._resolve(sub):
                self.found_subdomains.append(sub)
        self._log_result()

    def _resolve(self, subdomain):
        try:
            dns.resolver.resolve(subdomain, 'A')
            return True
        except:
            return False

    def _enumerate_crtsh(self):
        domain = self.target.domain
        url = f"https://crt.sh/?q={domain}&output=json"
        try:
            response = requests.get(url, timeout=10)
            if response.status_code != 200:
                return []
            data = response.json()
            subdomains = set()
            for entry in data:
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    if sub.endswith(domain):
                        subdomains.add(sub.strip())
            return list(subdomains)
        except Exception:
            return []

    def _bruteforce_subdomains(self):
        wordlist = ['mail', 'dev', 'test', 'api', 'www', 'vpn', 'login', 'academy', 'support', 'upload', 'blog', 'smtp']
        domain = self.target.domain
        return [f"{word}.{domain}" for word in wordlist]

    def get_output(self):
        return {"module": self.module_name, "subdomains": self.found_subdomains}

    def _log_result(self):
        table = Table(title=f"Subdomains for {self.target.domain}", style="header")
        table.add_column("Subdomain", style="info")
        for sub in self.found_subdomains:
            table.add_row(sub)
        console.print(table)

class SocialFootprint(ReconModule):
    def __init__(self, module_name, target):
        super().__init__(module_name)
        self.target = target
        self.found_profiles = []
        self.search_mentions = []

    def __sanitize_query(self, q):
        return q.replace("..", "").strip()

    def _platform_checks(self):
        domain = self.target.domain.split(".")[0]
        candidate_usernames = [domain, domain + "sec", domain + "official"]
        platforms = {
            "GitHub": "https://github.com/{}",
            "GitLab": "https://gitlab.com/{}",
            "Reddit": "https://www.reddit.com/user/{}",
            "Twitter": "https://x.com/{}",
            "Medium": "https://medium.com/@{}"
        }
        for user in candidate_usernames:
            for platform, url in platforms.items():
                final_url = url.format(user)
                try:
                    r = requests.get(final_url, headers={"User-Agent": "Mozilla/5.0"}, timeout=5)
                    if r.status_code == 200:
                        self.found_profiles.append({
                            "platform": platform,
                            "username": user,
                            "url": final_url
                        })
                except requests.RequestException:
                    pass

    def _search_mentions_engine(self):
        query = self.__sanitize_query(self.target.domain)
        with DDGS() as ddgs:
            for r in ddgs.text(query, max_results=10):
                self.search_mentions.append({
                    "title": r.get("title"),
                    "link": r.get("href")
                })

    def run(self):
        self._platform_checks()
        self._search_mentions_engine()
        self._log_result()

    def get_output(self):
        return {"module": self.module_name, "profiles": self.found_profiles, "mentions": self.search_mentions}

    def _log_result(self):
        table = Table(title=f"Social Footprint for {self.target.domain}", style="header")
        table.add_column("Platform", style="title")
        table.add_column("Username", style="info")
        table.add_column("URL", style="success")
        for profile in self.found_profiles:
            table.add_row(profile["platform"], profile["username"], profile["url"])
        console.print(table)

        mention_table = Table(title="Mentions", style="header")
        mention_table.add_column("Title", style="info")
        mention_table.add_column("Link", style="success")
        for mention in self.search_mentions:
            mention_table.add_row(mention["title"], mention["link"])
        console.print(mention_table)

class ReconManager:
    def __init__(self, target, modules=None, report_data=None):
        self.target = target
        self.modules = modules if modules else []
        self.__report_data = report_data if report_data else {}

    def add_module(self, module):
        self.modules.append(module)

    def run_all(self):
        console.print(Panel.fit("Running All Recon Modules", style="header"))
        for module in self.modules:
            try:
                module.run()
                self.__report_data[module.module_name] = module.get_output()
            except Exception as e:
                console.print(Panel.fit(
                    f"Module {module.module_name} failed: {e}",
                    style="error"
                ))
        console.print(Panel.fit("Recon Completed", style="success"))
        return self.__report_data


class PastelPinkTheme:
    
    bg_primary = "#FFF5F8"      
    bg_secondary = "#FFE5EC"   
    bg_accent = "#FFD6E0"       
    text_primary = "#4A4A4A"   
    text_secondary = "#8B7D8B"  
    accent_pink = "#FFB6C1"     
    accent_rose = "#FFC0CB"     
    border_color = "#FFB6C1"    
    button_hover = "#FF91A4"    


class ReconGUI:
    
    def __init__(self, root):
        self.root = root
        self.root.title("Domain Reconnaissance Tool")
        self.root.geometry("1000x700")
        self.root.configure(bg=PastelPinkTheme.bg_primary)
        
        self.target = None
        self.manager = None
        self.report_data = {}
        
        self._create_gui()
    
    def _create_gui(self):
        
        header_frame = tk.Frame(self.root, bg=PastelPinkTheme.bg_accent, height=80)
        header_frame.pack(fill=tk.X, padx=0, pady=0)
        header_frame.pack_propagate(False)
        
        title_label = tk.Label(
            header_frame,
            text="🔍 Domain Reconnaissance Tool",
            bg=PastelPinkTheme.bg_accent,
            fg=PastelPinkTheme.text_primary,
            font=('Segoe UI', 18, 'bold'),
            pady=20
        )
        title_label.pack()
        
        # Input section
        input_frame = tk.Frame(self.root, bg=PastelPinkTheme.bg_primary)
        input_frame.pack(fill=tk.X, padx=30, pady=20)
        
        tk.Label(
            input_frame,
            text="Domain:",
            bg=PastelPinkTheme.bg_primary,
            fg=PastelPinkTheme.text_primary,
            font=('Segoe UI', 11)
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        self.domain_entry = tk.Entry(
            input_frame,
            width=40,
            font=('Segoe UI', 11),
            bg="white",
            fg=PastelPinkTheme.text_primary,
            relief=tk.FLAT,
            borderwidth=2,
            highlightthickness=1,
            highlightbackground=PastelPinkTheme.border_color,
            highlightcolor=PastelPinkTheme.accent_pink
        )
        self.domain_entry.pack(side=tk.LEFT, padx=5)
        self.domain_entry.insert(0, "example.com")
        
        self.scan_button = tk.Button(
            input_frame,
            text="Start Recon",
            command=self._start_scan,
            bg=PastelPinkTheme.accent_pink,
            fg="white",
            font=('Segoe UI', 11, 'bold'),
            relief=tk.FLAT,
            padx=25,
            pady=8,
            cursor="hand2",
            activebackground=PastelPinkTheme.button_hover,
            activeforeground="white"
        )
        self.scan_button.pack(side=tk.LEFT, padx=10)
        
        # Status label
        self.status_label = tk.Label(
            input_frame,
            text="Ready",
            bg=PastelPinkTheme.bg_primary,
            fg=PastelPinkTheme.text_secondary,
            font=('Segoe UI', 9)
        )
        self.status_label.pack(side=tk.LEFT, padx=20)
        
        # Notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
        
        # Style the notebook
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TNotebook', background=PastelPinkTheme.bg_primary, borderwidth=0)
        style.configure('TNotebook.Tab', 
                       background=PastelPinkTheme.bg_secondary,
                       foreground=PastelPinkTheme.text_primary,
                       padding=[20, 10],
                       font=('Segoe UI', 10))
        style.map('TNotebook.Tab',
                 background=[('selected', PastelPinkTheme.accent_pink)],
                 foreground=[('selected', 'white')])
        
        # Create tabs
        self._create_dns_tab()
        self._create_whois_tab()
        self._create_subdomain_tab()
        self._create_social_tab()
    
    def _create_dns_tab(self):
        """Create DNS records tab."""
        frame = tk.Frame(self.notebook, bg=PastelPinkTheme.bg_primary)
        self.notebook.add(frame, text="DNS Records")
        
        self.dns_text = scrolledtext.ScrolledText(
            frame,
            bg="white",
            fg=PastelPinkTheme.text_primary,
            font=('Consolas', 10),
            relief=tk.FLAT,
            borderwidth=1,
            highlightthickness=1,
            highlightbackground=PastelPinkTheme.border_color
        )
        self.dns_text.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
    
    def _create_whois_tab(self):
        """Create WHOIS tab."""
        frame = tk.Frame(self.notebook, bg=PastelPinkTheme.bg_primary)
        self.notebook.add(frame, text="WHOIS")
        
        self.whois_text = scrolledtext.ScrolledText(
            frame,
            bg="white",
            fg=PastelPinkTheme.text_primary,
            font=('Consolas', 10),
            relief=tk.FLAT,
            borderwidth=1,
            highlightthickness=1,
            highlightbackground=PastelPinkTheme.border_color
        )
        self.whois_text.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
    
    def _create_subdomain_tab(self):
        """Create subdomain tab."""
        frame = tk.Frame(self.notebook, bg=PastelPinkTheme.bg_primary)
        self.notebook.add(frame, text="Subdomains")
        
        self.subdomain_text = scrolledtext.ScrolledText(
            frame,
            bg="white",
            fg=PastelPinkTheme.text_primary,
            font=('Consolas', 10),
            relief=tk.FLAT,
            borderwidth=1,
            highlightthickness=1,
            highlightbackground=PastelPinkTheme.border_color
        )
        self.subdomain_text.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
    
    def _create_social_tab(self):
        """Create social footprint tab."""
        frame = tk.Frame(self.notebook, bg=PastelPinkTheme.bg_primary)
        self.notebook.add(frame, text="Social Footprint")
        
        self.social_text = scrolledtext.ScrolledText(
            frame,
            bg="white",
            fg=PastelPinkTheme.text_primary,
            font=('Consolas', 10),
            relief=tk.FLAT,
            borderwidth=1,
            highlightthickness=1,
            highlightbackground=PastelPinkTheme.border_color
        )
        self.social_text.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
    
    def _update_status(self, message):
        """Update status label."""
        self.status_label.config(text=message)
        self.root.update_idletasks()
    
    def _start_scan(self):
        """Start the reconnaissance scan."""
        domain = self.domain_entry.get().strip()
        if not domain:
            messagebox.showerror("Error", "Please enter a domain name")
            return
        
        # Clean domain
        domain = domain.replace("https://", "").replace("http://", "").replace("www.", "")
        
        # Disable button and clear displays
        self.scan_button.config(state=tk.DISABLED)
        self._update_status("Scanning...")
        
        # Clear all text areas
        for text_widget in [self.dns_text, self.whois_text, self.subdomain_text, self.social_text]:
            text_widget.config(state=tk.NORMAL)
            text_widget.delete(1.0, tk.END)
            text_widget.config(state=tk.DISABLED)
        
        # Run in background thread
        thread = threading.Thread(target=self._scan_worker, args=(domain,))
        thread.daemon = True
        thread.start()
    
    def _scan_worker(self, domain):
        """Background worker for scanning."""
        try:
            # Create target and modules
            target = Target(domain, None, "passive_recon")
            dns_module = DNSRecon("DNS Enumeration", target)
            whois_module = WhoisRecon("WHOIS Lookup", target)
            subdomain_module = SubdomainFinder("Subdomain Finder", target)
            social_module = SocialFootprint("Social Footprint", target)
            
            # Create manager
            report_data = {}
            manager = ReconManager(target, [], report_data)
            manager.add_module(dns_module)
            manager.add_module(whois_module)
            manager.add_module(subdomain_module)
            manager.add_module(social_module)
            
            # Run all modules (this will also print to console via _log_result)
            report_data = manager.run_all()
            
            # Display results in GUI
            self.root.after(0, lambda: self._display_results(report_data, domain))
            
            self.root.after(0, lambda: self._update_status("Scan complete!"))
            self.root.after(0, lambda: self.scan_button.config(state=tk.NORMAL))
            
        except Exception as e:
            self.root.after(0, lambda: self._update_status("Scan failed"))
            self.root.after(0, lambda: self.scan_button.config(state=tk.NORMAL))
            self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
    
    def _display_results(self, report_data, domain):
        """Display results in respective tabs."""
        # DNS Records
        if "DNS Enumeration" in report_data:
            dns_data = report_data["DNS Enumeration"]
            self.dns_text.config(state=tk.NORMAL)
            self.dns_text.insert(tk.END, f"DNS Records for {domain}\n")
            self.dns_text.insert(tk.END, "=" * 60 + "\n\n")
            for rtype, values in dns_data.items():
                self.dns_text.insert(tk.END, f"{rtype}:\n")
                for value in values:
                    self.dns_text.insert(tk.END, f"  • {value}\n")
                self.dns_text.insert(tk.END, "\n")
            self.dns_text.config(state=tk.DISABLED)
        
        # WHOIS
        if "WHOIS Lookup" in report_data:
            whois_data = report_data["WHOIS Lookup"]
            self.whois_text.config(state=tk.NORMAL)
            self.whois_text.insert(tk.END, f"WHOIS Data for {domain}\n")
            self.whois_text.insert(tk.END, "=" * 60 + "\n\n")
            self.whois_text.insert(tk.END, json.dumps(whois_data, indent=2))
            self.whois_text.config(state=tk.DISABLED)
        
        # Subdomains
        if "Subdomain Finder" in report_data:
            subdomain_data = report_data["Subdomain Finder"]
            self.subdomain_text.config(state=tk.NORMAL)
            self.subdomain_text.insert(tk.END, f"Subdomains for {domain}\n")
            self.subdomain_text.insert(tk.END, "=" * 60 + "\n\n")
            if "subdomains" in subdomain_data:
                for sub in subdomain_data["subdomains"]:
                    self.subdomain_text.insert(tk.END, f"  • {sub}\n")
            self.subdomain_text.config(state=tk.DISABLED)
        
        # Social Footprint
        if "Social Footprint" in report_data:
            social_data = report_data["Social Footprint"]
            self.social_text.config(state=tk.NORMAL)
            self.social_text.insert(tk.END, f"Social Footprint for {domain}\n")
            self.social_text.insert(tk.END, "=" * 60 + "\n\n")
            
            if "profiles" in social_data:
                self.social_text.insert(tk.END, "Profiles:\n")
                for profile in social_data["profiles"]:
                    self.social_text.insert(tk.END, f"  Platform: {profile['platform']}\n")
                    self.social_text.insert(tk.END, f"  Username: {profile['username']}\n")
                    self.social_text.insert(tk.END, f"  URL: {profile['url']}\n\n")
            
            if "mentions" in social_data:
                self.social_text.insert(tk.END, "Mentions:\n")
                for mention in social_data["mentions"]:
                    self.social_text.insert(tk.END, f"  Title: {mention.get('title', 'N/A')}\n")
                    self.social_text.insert(tk.END, f"  Link: {mention.get('link', 'N/A')}\n\n")
            
            self.social_text.config(state=tk.DISABLED)


def main():
    """Launch GUI application."""
    root = tk.Tk()
    app = ReconGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
