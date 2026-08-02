import re
import os
import json
import logging
import requests

# Set up logging for this module
logger = logging.getLogger(__name__)

# MITRE ATT&CK Patterns (Standard Enterprise threats - fallback)
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

# MITRE ATLAS Patterns (AI / Machine Learning specific threats - fallback)
MITRE_ATLAS_PATTERNS = {
    "AML.T0051 (LLM Jailbreak)": {
        "tactic": "Impact",
        "pattern": r"\b(jailbreak|jailbreaking|jailbroken)\b"
    },
    "AML.T0054 (LLM Prompt Injection)": {
        "tactic": "Initial Access",
        "pattern": r"\b(prompt injection|indirect prompt injection|malicious prompt)\b"
    },
    "AML.T0040 (ML Model Poisoning)": {
        "tactic": "ML Attack Staging",
        "pattern": r"\b(poisoning|data poisoning|poisoned dataset|poisoned training|model poisoning)\b"
    },
    "AML.T0018 (Adversarial Input Evasion)": {
        "tactic": "Defense Evasion",
        "pattern": r"\b(evasion|adversarial perturbation|adversarial input|evading model)\b"
    },
    "AML.T0024 (Exfiltration)": {
        "tactic": "Exfiltration",
        "pattern": r"\b(exfiltrate|exfiltration|model leakage|leak weights|weight theft|leak data)\b"
    },
    "AML.T0055 (Model Serialization Attack)": {
        "tactic": "Execution",
        "pattern": r"\b(model serialization|pickle exploit|safetensors exploit|malicious model|compromised model)\b"
    }
}

def call_gemini_mitre_mapping(title, summary, api_key):
    """Call Gemini API to semantically determine the MITRE ATT&CK or MITRE ATLAS framework and mapping."""
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-3.6-flash:generateContent?key={api_key}"
    headers = {"Content-Type": "application/json"}
    
    prompt = (
        "You are a cybersecurity expert analyzing threat intelligence feeds.\n"
        "Your task is to map this news article to relevant security frameworks.\n\n"
        
        "Rules:\n"
        "1. If the article is a weekly news recap, newsletter, bulletin, or generic research paper/summary list (not a specific threat incident or CVE), return 'NONE' as the framework and an empty list of techniques.\n"
        "2. If the article describes an AI, LLM, or Machine Learning vulnerability, exploit, or threat (e.g. jailbreaking, prompt injection, model poisoning), use the 'MITRE ATLAS' framework and map to relevant techniques (e.g., AML.T0054 (LLM Prompt Injection)).\n"
        "3. Otherwise, use the 'MITRE ATT&CK' framework and map to standard enterprise techniques (e.g. T1566 (Phishing)).\n\n"
        
        "Article to Analyze:\n"
        f"Title: {title}\n"
        f"Summary: {summary}\n\n"
        
        "Format the techniques in the list exactly like this: '[Tactic Name] ID (Technique Name)'.\n"
        "Return a JSON object in this format:\n"
        '{\n  "framework": "MITRE ATT&CK" or "MITRE ATLAS" or "NONE",\n  "techniques": [" [Tactic] Technique_ID (Technique Name)", ...]\n}'
    )
    
    payload = {
        "contents": [
            {
                "parts": [
                    {"text": prompt}
                ]
            }
        ],
        "generationConfig": {
            "responseMimeType": "application/json"
        }
    }
    
    try:
        response = requests.post(url, headers=headers, json=payload, timeout=15)
        response.raise_for_status()
        result = response.json()
        text_content = result["candidates"][0]["content"]["parts"][0]["text"]
        data = json.loads(text_content)
        return data.get("framework", "MITRE ATT&CK"), data.get("techniques", [])
    except Exception as e:
        logger.warning(f"Failed to perform semantic MITRE mapping using Gemini: {e}. Falling back to regex keyword mapping.")
        return None, None

def map_mitre_attack(title, summary):
    """Scan title and summary and return the framework type and unique matching MITRE mappings."""
    # Check if Gemini API key is available for semantic threat mapping
    gemini_api_key = os.getenv("GEMINI_API_KEY")
    if gemini_api_key and gemini_api_key.strip():
        framework, techniques = call_gemini_mitre_mapping(title, summary or "", gemini_api_key.strip())
        if framework is not None and techniques is not None:
            if framework == "NONE":
                return "MITRE ATT&CK", []
            logger.info(f"[GEMINI MITRE MAP] Mapped \"{title}\" to {framework} ({len(techniques)} matches)")
            return framework, techniques

    # Fallback: Regex Keyword Mapping
    title_lower = title.lower()
    exclusions = ["weekly", "newsletter", "bulletin", "recap", "research", "researcher", "researchers"]
    if any(ex in title_lower for ex in exclusions):
        return "MITRE ATT&CK", []
        
    combined_text = f"{title} {summary}".lower()
    
    # Determine if it is an AI use case (requires MITRE ATLAS mapping)
    ai_keywords = r"\b(ai|llm|llms|chatgpt|copilot|prompt\s+injection|jailbreak|jailbreaking|generative\s+ai|genai|machine\s+learning|artificial\s+intelligence|adversarial\s+machine\s+learning)\b"
    is_ai = bool(re.search(ai_keywords, combined_text))
    
    framework = "MITRE ATLAS" if is_ai else "MITRE ATT&CK"
    patterns = MITRE_ATLAS_PATTERNS if is_ai else MITRE_ATTACK_PATTERNS
    
    matches = []
    for technique, info in patterns.items():
        if re.search(info["pattern"], combined_text):
            formatted_mapping = f"[{info['tactic']}] {technique}"
            matches.append(formatted_mapping)
            
    return framework, matches
