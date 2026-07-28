import unittest
from mitre_map import map_mitre_attack

class TestMitreAttackMapping(unittest.TestCase):
    def test_phishing_mapping(self):
        title = "New Phishing Campaign Targets Financial Institutions"
        summary = "Attackers are using malicious email attachments containing document lures to steal employee credentials."
        framework, matches = map_mitre_attack(title, summary)
        self.assertEqual(framework, "MITRE ATT&CK")
        self.assertIn("[Initial Access] T1566 (Phishing)", matches)
        self.assertIn("[Initial Access] T1078 (Valid Accounts)", matches)

    def test_exploit_mapping(self):
        title = "Critical Auth Bypass Flaw Found in Apache Server"
        summary = "The zero-day vulnerability, tracked as CVE-2026-1234, allows remote code execution (RCE) on affected hosts."
        framework, matches = map_mitre_attack(title, summary)
        self.assertEqual(framework, "MITRE ATT&CK")
        self.assertIn("[Initial Access] T1190 (Exploit Public-Facing Application)", matches)

    def test_ransomware_mapping(self):
        title = "LockBit Ransomware Hits Healthcare Provider"
        summary = "The threat actors encrypted files and demanded a ransom payment, dropping a ransom note in every folder."
        framework, matches = map_mitre_attack(title, summary)
        self.assertEqual(framework, "MITRE ATT&CK")
        self.assertIn("[Impact] T1486 (Data Encrypted for Impact)", matches)

    def test_unmapped(self):
        title = "Google Announces Security Policy Changes"
        summary = "The company is updating its internal guidelines for third-party security audits starting next quarter."
        framework, matches = map_mitre_attack(title, summary)
        self.assertEqual(framework, "MITRE ATT&CK")
        self.assertEqual(len(matches), 0)

    def test_exclusions(self):
        # Excluded keywords: Weekly, Newsletter, Bulletin, Recap, Research, Researcher, Researchers
        title1 = "Cybersecurity Weekly: Zero-Day Exploit Released"
        title2 = "Threat Intelligence Bulletin: New Malware Campaign"
        title3 = "GitLab Exploit Research Published by Security Analysts"
        summary = "Attackers are using phishing emails containing malicious attachments to gain initial access."
        
        _, matches1 = map_mitre_attack(title1, summary)
        _, matches2 = map_mitre_attack(title2, summary)
        _, matches3 = map_mitre_attack(title3, summary)
        
        self.assertEqual(len(matches1), 0)
        self.assertEqual(len(matches2), 0)
        self.assertEqual(len(matches3), 0)

    def test_mitre_atlas_ai(self):
        title = "New LLM Prompt Injection Attacks Evade Guardrails"
        summary = "Security researchers demonstrated indirect prompt injection techniques to jailbreak generative AI models."
        framework, matches = map_mitre_attack(title, summary)
        self.assertEqual(framework, "MITRE ATLAS")
        self.assertIn("[Initial Access] AML.T0054 (LLM Prompt Injection)", matches)
        self.assertIn("[Impact] AML.T0051 (LLM Jailbreak)", matches)

if __name__ == "__main__":
    unittest.main()
