import re
from datetime import datetime, timedelta, timezone

STOP_WORDS = {
    'a', 'an', 'the', 'in', 'on', 'to', 'for', 'of', 'and', 'or', 'is', 'are', 
    'with', 'by', 'from', 'at', 'about', 'as', 'into', 'that', 'this', 'these', 
    'those', 'it', 'its', 'new', 'how', 'why', 'what', 'who', 'which', 'was', 
    'were', 'be', 'been', 'has', 'have', 'had', 'to', 'from', 'over', 'out', 'up'
}

def tokenize(text):
    """Tokenize a text string into lowercase words, removing stop words and short elements."""
    if not text:
        return set()
    # Find all words/alphanumeric strings
    words = re.findall(r'\b\w+\b', text.lower())
    # Filter out stop words, digits, and short tokens (allowing 2-letter tokens like 'ai', 'ip', 'c2')
    tokens = {w for w in words if w not in STOP_WORDS and len(w) >= 2 and not w.isdigit()}
    return tokens

def overlap_coefficient(text1, text2):
    """Calculate the Overlap Coefficient between two text strings."""
    tokens1 = tokenize(text1)
    tokens2 = tokenize(text2)
    
    if not tokens1 or not tokens2:
        return 0.0
        
    intersection = tokens1.intersection(tokens2)
    return len(intersection) / min(len(tokens1), len(tokens2))

def is_duplicate(new_title, new_summary, seen_items, days_limit=5, similarity_threshold=0.58, summary_threshold=0.60):
    """Check if the article is a duplicate of any article posted in the last days_limit days based on Title or Summary."""
    now = datetime.now(timezone.utc)
    recent_items = []
    
    # Filter seen items to only compare with recent ones
    for item in seen_items:
        created_at_str = item.get('created_at')
        if not created_at_str:
            continue
        try:
            created_at = datetime.fromisoformat(created_at_str)
            # Make sure created_at is timezone-aware
            if created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=timezone.utc)
            if now - created_at <= timedelta(days=days_limit):
                recent_items.append(item)
        except Exception:
            continue

    # Compare similarity
    for item in recent_items:
        # 1. Compare titles (using updated threshold)
        title_sim = overlap_coefficient(new_title, item['title'])
        if title_sim >= similarity_threshold:
            return item
            
        # 2. Compare summaries (if summary field is present in both)
        old_summary = item.get('summary')
        if new_summary and old_summary:
            summary_sim = overlap_coefficient(new_summary, old_summary)
            if summary_sim >= summary_threshold:
                return item
            
    return None
