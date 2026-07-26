import re

# Dictionary mapping technique ID and name to its parent Tactic and case-insensitive regex pattern
MITRE_ATTACK_PATTERNS = {
    "T1566 (Phishing)": {
        "tactic": "Initial Access",
        "pattern": r"\b(phishing|spearphishing|vishing|smishing|email lure|phish|lures?|malicious attachment)\b"
    },
    "T1190 (Exploit Public-Facing Application)": {
        "tactic": "Initial Access",
        "pattern": r"\b(zero-day|exploit|cve-\d{4}-\d{4,7}|rce|sqli|injection|xss|cross-site scripting|directory traversal|auth bypass|authentication bypass|vulnerability|vulnerabilities|flaw)\b"
    },
    "T1195 (Supply Chain Compromise)": {
        "tactic": "Initial Access",
        "pattern": r"\b(supply chain|malicious package|npm package|pypi package|typosquatting|backdoored sdk|third-party package|dependency|dependencies)\b"
    },
    "T1078 (Valid Accounts)": {
        "tactic": "Initial Access",
        "pattern": r"\b(compromised credentials|credential leak|password leak|exposed database|data leak|data exposure|credential stuffing|exposed credentials|valid accounts|stolen credentials|steal\s+(\w+\s+)?credentials|credential theft)\b"
    },
    "T1059 (Command and Scripting Interpreter)": {
        "tactic": "Execution",
        "pattern": r"\b(powershell|cmd\.exe|bash script|python script|macro|scripting interpreter|command line)\b"
    },
    "T1129 (Shared Modules)": {
        "tactic": "Execution",
        "pattern": r"\b(dll hijacking|dll side-loading|malicious dll)\b"
    },
    "T1543 (Create or Modify System Process)": {
        "tactic": "Persistence",
        "pattern": r"\b(service creation|systemd daemon|windows service|modify service)\b"
    },
    "T1547 (Registry Run Keys / Startup Folder)": {
        "tactic": "Persistence",
        "pattern": r"\b(registry run key|startup folder|persistence mechanism|auto-run|boot survival)\b"
    },
    "T1068 (Exploitation for Privilege Escalation)": {
        "tactic": "Privilege Escalation",
        "pattern": r"\b(privilege escalation|root escalation|local privilege escalation|lpe|escalation of privilege)\b"
    },
    "T1562 (Impair Defenses)": {
        "tactic": "Defense Evasion",
        "pattern": r"\b(disable defender|antivirus bypass|av evasion|bypass waf|tamper logs|security bypass|evading detection)\b"
    },
    "T1027 (Obfuscated Files or Information)": {
        "tactic": "Defense Evasion",
        "pattern": r"\b(obfuscated|encrypted payload|base64 encoded|packed binary|stealthy packaging)\b"
    },
    "T1555 (Credentials from Password Stores)": {
        "tactic": "Credential Access",
        "pattern": r"\b(info-stealer|credential stealer|stealer malware|password stealer|redline|vidar|lumma|agent tesla|raccoon stealer|password manager)\b"
    },
    "T1110 (Brute Force)": {
        "tactic": "Credential Access",
        "pattern": r"\b(brute force|credential stuffing|password spraying|bruteforcing)\b"
    },
    "T1071 (Application Layer Protocol)": {
        "tactic": "Command and Control",
        "pattern": r"\b(c2 channel|dns tunneling|http command and control|c2 communication)\b"
    },
    "T1567 (Exfiltration Over Web Service)": {
        "tactic": "Exfiltration",
        "pattern": r"\b(data exfiltration|exfiltrated|stole data|mega\.nz|dropbox upload|exfiltrating data)\b"
    },
    "T1486 (Data Encrypted for Impact)": {
        "tactic": "Impact",
        "pattern": r"\b(ransomware|locked files|decryptor|ransom note|encrypting files)\b"
    },
    "T1491 (Defacement)": {
        "tactic": "Impact",
        "pattern": r"\b(website defacement|defaced|defacing)\b"
    },
    "T1529 (System Shutdown/Reboot)": {
        "tactic": "Impact",
        "pattern": r"\b(wiper|wiper malware|system wipe|shutdown host)\b"
    }
}

def map_mitre_attack(title, summary):
    """Scan title and summary and return unique matching MITRE ATT&CK mappings in '[Tactic] Technique' format."""
    matches = []
    combined_text = f"{title} {summary}".lower()
    
    for technique, info in MITRE_ATTACK_PATTERNS.items():
        if re.search(info["pattern"], combined_text):
            formatted_mapping = f"[{info['tactic']}] {technique}"
            matches.append(formatted_mapping)
            
    return matches
