import re
import os
import json
import logging
import time
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
    """Call Gemini API to evaluate applicability and determine MITRE ATT&CK or MITRE ATLAS framework mapping."""
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-3.5-flash-lite:generateContent?key={api_key}"
    headers = {"Content-Type": "application/json"}
    
    prompt = (
        "You are a Tier-3 Cyber Threat Intelligence (CTI) analyst analyzing threat feeds.\n"
        "Your task is to determine whether an article represents adversary behavior that is APPLICABLE for MITRE ATT&CK or MITRE ATLAS framework mapping, and if so, classify it.\n\n"
        
        "Step 1: Assess Applicability\n"
        "MITRE mapping is ONLY applicable if the article reports an active cyberattack, threat actor campaign, exploit in the wild, malware mechanism, or adversary TTP (Tactics, Techniques, and Procedures).\n"
        "MITRE mapping is NOT applicable ('NONE') for:\n"
        "- Vendor patch releases, security updates, out-of-band (OOB) updates, bug fixes, or emergency release notes (e.g., 'Oracle Issues Emergency Java Update', 'Microsoft releases Windows OOB updates').\n"
        "- Corporate, business, legal, certificate trust, or market announcements (e.g., 'eMudhra Exits Global SSL/TLS Certificate Business', vendor distrust actions, acquisitions).\n"
        "- Compliance, regulatory, policy, or governance notices.\n"
        "- Weekly digests, news recaps, bulletins, research papers, or tool comparison lists.\n"
        "- General vulnerability disclosures or theoretical flaws without reported in-the-wild adversarial exploitation.\n\n"
        
        "Step 2: Framework Selection & Technique Mapping (Only if Applicable)\n"
        "- If the threat involves Artificial Intelligence, LLMs, or Machine Learning (e.g. prompt injection, jailbreak, model poisoning), use 'MITRE ATLAS' and map to relevant techniques (e.g., AML.T0054 (LLM Prompt Injection)).\n"
        "- For all other standard enterprise cyber threats, use 'MITRE ATT&CK' and map to relevant techniques (e.g., T1566 (Phishing), T1190 (Exploit Public-Facing Application)).\n"
        "- If not applicable, return 'NONE' as the framework and an empty list of techniques.\n\n"
        
        "Article to Analyze:\n"
        f"Title: {title}\n"
        f"Summary: {summary}\n\n"
        
        "Format the techniques in the list exactly like this: '[Tactic Name] ID (Technique Name)'.\n"
        "Return a JSON object in this format:\n"
        '{\n  "applicable": true or false,\n  "reason": "short explanation of applicability decision",\n  "framework": "MITRE ATT&CK" or "MITRE ATLAS" or "NONE",\n  "techniques": ["[Tactic] Technique_ID (Technique Name)", ...]\n}'
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
    
    max_retries = 3
    for attempt in range(max_retries):
        try:
            response = requests.post(url, headers=headers, json=payload, timeout=25)
            if response.status_code == 429:
                wait_time = 5 * (attempt + 1)
                logger.warning(f"Gemini API rate limit reached (HTTP 429). Retrying in {wait_time}s (Attempt {attempt + 1}/{max_retries})...")
                time.sleep(wait_time)
                continue
            response.raise_for_status()
            result = response.json()
            text_content = result["candidates"][0]["content"]["parts"][0]["text"]
            data = json.loads(text_content)
            
            # Pacing delay to stay comfortably under 15 RPM free-tier quota
            time.sleep(4)
            
            applicable = data.get("applicable", True)
            framework = data.get("framework", "NONE")
            techniques = data.get("techniques", [])
            reason = data.get("reason", "")
            
            if not applicable or framework == "NONE":
                logger.info(f"[GEMINI MITRE MAP] '{title}' evaluated as NOT APPLICABLE for MITRE: {reason}")
                return "NONE", []
                
            return framework, techniques
        except requests.exceptions.RequestException as e:
            if attempt < max_retries - 1 and hasattr(e, 'response') and e.response is not None and e.response.status_code == 429:
                wait_time = 5 * (attempt + 1)
                logger.warning(f"Gemini API rate limit reached (HTTP 429). Retrying in {wait_time}s (Attempt {attempt + 1}/{max_retries})...")
                time.sleep(wait_time)
                continue
            logger.warning(f"Failed to perform semantic MITRE mapping using Gemini: {e}. Falling back to regex keyword mapping.")
            return None, None
        except Exception as e:
            logger.warning(f"Failed to perform semantic MITRE mapping using Gemini: {e}. Falling back to regex keyword mapping.")
            return None, None
    return None, None

def map_mitre_attack(title, summary):
    """Scan title and summary and return the framework type and unique matching MITRE mappings."""
    # Check if Gemini API key is available for semantic threat mapping
    gemini_api_key = os.getenv("GEMINI_API_KEY")
    if gemini_api_key and gemini_api_key.strip():
        framework, techniques = call_gemini_mitre_mapping(title, summary or "", gemini_api_key.strip())
        if framework is not None and techniques is not None:
            if framework == "NONE" or not techniques:
                return "MITRE ATT&CK", []
            logger.info(f"[GEMINI MITRE MAP] Mapped \"{title}\" to {framework} ({len(techniques)} matches)")
            return framework, techniques

    # Fallback: Regex Keyword Mapping
    title_lower = title.lower()
    
    # 1. Unconditional digest / research exclusions
    exclusions = ["weekly", "newsletter", "bulletin", "recap", "research", "researcher", "researchers"]
    if any(ex in title_lower for ex in exclusions):
        return "MITRE ATT&CK", []

    # 2. Non-adversary vendor patch, OOB update, or corporate announcements without active exploitation
    non_adversary_pattern = r"\b(oob|emergency|security)\s+(\w+\s+)?(update|updates|patch|patches)\b|\b(exits|distrust)\b"
    if re.search(non_adversary_pattern, title_lower) and not re.search(r"\b(exploited|in the wild|zero-day|0-day|active attack)\b", title_lower):
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
