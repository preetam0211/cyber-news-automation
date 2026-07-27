import unittest
from datetime import datetime, timezone
from deduplication import tokenize, overlap_coefficient, is_duplicate

class TestDeduplication(unittest.TestCase):
    def test_tokenize(self):
        title = "Critical zero-day vulnerability in Google Chrome exploited in the wild"
        tokens = tokenize(title)
        self.assertIn("critical", tokens)
        self.assertIn("google", tokens)
        self.assertIn("chrome", tokens)
        # Exclude stop words
        self.assertNotIn("in", tokens)
        self.assertNotIn("the", tokens)
        # Include 2-letter tokens like 'ai'
        title_ai = "Hermes AI agent used"
        tokens_ai = tokenize(title_ai)
        self.assertIn("ai", tokens_ai)
        
    def test_overlap_coefficient(self):
        title1 = "Critical zero-day vulnerability in Google Chrome exploited in the wild"
        title2 = "Google Chrome zero-day vulnerability exploited in attacks, patch now"
        
        score = overlap_coefficient(title1, title2)
        print(f"Overlap score: {score}")
        self.assertGreaterEqual(score, 0.65)
        
    def test_is_duplicate(self):
        seen_items = [
            {
                "guid": "guid1",
                "title": "Critical zero-day vulnerability in Google Chrome exploited in the wild",
                "link": "link1",
                "published": "date1",
                "source": "The Hacker News",
                "created_at": datetime.now(timezone.utc).isoformat()
            }
        ]
        
        new_title = "Google Chrome zero-day vulnerability exploited in attacks, patch now"
        dup = is_duplicate(new_title, None, seen_items, days_limit=5, similarity_threshold=0.65)
        self.assertIsNotNone(dup)
        self.assertEqual(dup["guid"], "guid1")

    def test_is_duplicate_hermes(self):
        seen_items = [
            {
                "guid": "guid_hermes",
                "title": "Hermes AI agent used to automate attack on Thai Finance Ministry",
                "link": "link1",
                "published": "date1",
                "source": "BleepingComputer",
                "created_at": datetime.now(timezone.utc).isoformat()
            }
        ]
        new_title = "Hacker Runs Hermes AI Agent Unattended for Post-Exploitation at Thai Finance Ministry"
        # Checking Hermes case using updated default threshold (0.58) and 2-letter tokens
        dup = is_duplicate(new_title, None, seen_items, days_limit=5)
        self.assertIsNotNone(dup)
        self.assertEqual(dup["guid"], "guid_hermes")

    def test_is_duplicate_gitlab(self):
        # Test case where titles are very different but summaries match (GitLab RCE case)
        summary_text = "A newly disclosed exploit chain in GitLab shows how two long-buried memory-safety flaws in a Ruby JSON parsing library, Oj, could be combined to achieve remote code execution on default GitLab installations"
        seen_items = [
            {
                "guid": "guid_gitlab",
                "title": "Researcher Publishes GitLab RCE PoC Letting Authenticated Users Run Commands as Git",
                "summary": summary_text,
                "link": "link1",
                "published": "date1",
                "source": "The Hacker News",
                "created_at": datetime.now(timezone.utc).isoformat()
            }
        ]
        new_title = "GitLab Vulnerabilities Allow Attackers to Execute Remote Code on Default GitLab Installations"
        new_summary = summary_text
        dup = is_duplicate(new_title, new_summary, seen_items, days_limit=5)
        self.assertIsNotNone(dup)
        self.assertEqual(dup["guid"], "guid_gitlab")

if __name__ == "__main__":
    unittest.main()
