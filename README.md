# SQLiScannerGUI
SQL Injection Scanner Pro Advanced Web Vulnerability Detection Tool  

Overview:

SQL Injection Scanner Pro is a sophisticated security assessment tool designed to identify SQL injection vulnerabilities in web applications. Combining automated scanning with comprehensive reporting, this tool helps security professionals and developers uncover database security flaws before attackers can exploit them.  

Key Features:  
Hybrid Search Engine  Simultaneously queries Bing and DuckDuckGo  Discovers potentially vulnerable URLs using advanced Google dorks  Smart Vulnerability Detection  Tests for 8+ SQLi attack vectors (Error-based, Time-based, Boolean, etc.)  Auto-detects database errors in responses  Supports parameter tampering with 15+ payload types  Comprehensive Dork Generator  50+ built-in dork templates    

CMS-specific patterns (WordPress, Joomla, Drupal)  Integrated Workflow  Automatic saving of vulnerable targets  One-click SQLMap integration for deeper exploitation  Exportable reports (HTML/TXT)  Security-Focused Design  Adjustable scan speed to avoid detection  Detailed activity logging  No proxy requirements (direct scanning)  

Technical Specifications:  
Platform: Windows/macOS/Linux (Python 3.8+)  Output Formats: TXT, HTML  Scan Modes: Fast (surface checks), Deep (full parameter testing)  Supported Databases: MySQL, MSSQL, Oracle, PostgreSQL  

Use Cases: 

✔ Web application penetration testing 
✔ Security hardening assessments 
✔ Educational/research purposes 
✔ Vulnerability monitoring  

Ethical Notice: 

This tool is intended for authorized security testing only. Always obtain proper permissions before scanning any website or application


Installation and Run:
pip install -r requirements.txt
python SQLiScannerGUI.py

Advanced web vulnerability scanner with:
- Dork generation
- SQLi detection
- Reporting

## Installation
```bash
git clone https://github.com/InfinityTeq/SQLiScannerGUI.git
cd SQLiScannerGUI
pip install -r requirements.txt
python SQLiScannerGUI.py

OR

Compile to EXE file
pyinstaller SQLiScannerGUI.py --noconsole --onefile --icon "3vl.ico" --noconfirm
