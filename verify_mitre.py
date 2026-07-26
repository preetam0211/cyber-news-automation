import unittest
from mitre_map import map_mitre_attack

class TestMitreAttackMapping(unittest.TestCase):
    def test_phishing_mapping(self):
        title = "New Phishing Campaign Targets Financial Institutions"
        summary = "Attackers are using malicious email attachments containing document lures to steal employee credentials."
        matches = map_mitre_attack(title, summary)
        self.assertIn("T1566 (Phishing)", matches)
        self.assertIn("T1078 (Valid Accounts)", matches)

    def test_exploit_mapping(self):
        title = "Critical Auth Bypass Flaw Found in Apache Server"
        summary = "The zero-day vulnerability, tracked as CVE-2026-1234, allows remote code execution (RCE) on affected hosts."
        matches = map_mitre_attack(title, summary)
        self.assertIn("T1190 (Exploit Public-Facing Application)", matches)

    def test_ransomware_mapping(self):
        title = "LockBit Ransomware Hits Healthcare Provider"
        summary = "The threat actors encrypted files and demanded a ransom payment, dropping a ransom note in every folder."
        matches = map_mitre_attack(title, summary)
        self.assertIn("T1486 (Data Encrypted for Impact)", matches)

    def test_unmapped(self):
        title = "Google Announces Security Policy Changes"
        summary = "The company is updating its internal guidelines for third-party security audits starting next quarter."
        matches = map_mitre_attack(title, summary)
        self.assertEqual(len(matches), 0)

if __name__ == "__main__":
    unittest.main()
