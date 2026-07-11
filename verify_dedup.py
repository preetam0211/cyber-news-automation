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
        dup = is_duplicate(new_title, seen_items, days_limit=5, similarity_threshold=0.65)
        self.assertIsNotNone(dup)
        self.assertEqual(dup["guid"], "guid1")

if __name__ == "__main__":
    unittest.main()
