import re
import os
import json
import logging
import requests
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

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

def call_gemini_semantic_check(new_title, new_summary, recent_items, api_key):
    """Call Gemini API to semantically determine if the new article is a duplicate of recent items."""
    # Use the stable production endpoint for gemini-3.6-flash
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-3.6-flash:generateContent?key={api_key}"
    headers = {"Content-Type": "application/json"}
    
    # Construct prompt listing the candidate duplicates
    prompt = (
        "You are a cybersecurity expert analyzing threat intelligence feeds. "
        "Your task is to determine if a newly parsed news article describes the exact same security vulnerability, "
        "data breach, cyberattack, or general cybersecurity news event as any of the recently processed articles.\n\n"
        
        "New Article to Check:\n"
        f"Title: {new_title}\n"
        f"Summary: {new_summary}\n\n"
        
        "Recently Processed Articles:\n"
    )
    
    for idx, item in enumerate(recent_items):
        prompt += f"Article ID: {item['guid']}\nTitle: {item['title']}\nSummary: {item.get('summary', '')}\n---\n"
        
    prompt += (
        "\nCompare the new article against the recently processed articles. "
        "Two articles are duplicates if they cover the exact same security incident or release (even if phrased differently or focusing on different details like vendor disclosure vs exploit analysis).\n"
        "Return a JSON object in this format:\n"
        '{\n  "duplicate": true or false,\n  "matched_id": "the Article ID of the duplicate matching article (if duplicate is true, else null)"\n}'
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
        response = requests.post(url, headers=headers, json=payload, timeout=25)
        response.raise_for_status()
        result = response.json()
        text_content = result["candidates"][0]["content"]["parts"][0]["text"]
        data = json.loads(text_content)
        return data
    except Exception as e:
        logger.warning(f"Failed to perform semantic check using Gemini API: {e}. Falling back to keyword matching.")
        return None

def is_duplicate(new_title, new_summary, seen_items, days_limit=5, similarity_threshold=0.65, summary_threshold=0.60):
    """Check if the article is a duplicate of any article posted in the last days_limit days."""
    now = datetime.now(timezone.utc)
    recent_items = []
    
    # Filter seen items to only compare with recent ones
    for item in seen_items:
        created_at_str = item.get('created_at')
        if not created_at_str:
            continue
        try:
            created_at = datetime.fromisoformat(created_at_str)
            if created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=timezone.utc)
            if now - created_at <= timedelta(days=days_limit):
                recent_items.append(item)
        except Exception:
            continue

    if not recent_items:
        return None

    # Check if Gemini API key is available for semantic deduplication
    gemini_api_key = os.getenv("GEMINI_API_KEY")
    if gemini_api_key and gemini_api_key.strip():
        # Attempt semantic check
        result = call_gemini_semantic_check(new_title, new_summary or "", recent_items, gemini_api_key.strip())
        if result and result.get("duplicate") and result.get("matched_id"):
            matched_id = result["matched_id"]
            for item in recent_items:
                if item.get("guid") == matched_id:
                    logger.info(f"[GEMINI SEMANTIC DEDUP] Match found for \"{new_title}\" -> \"{item['title']}\"")
                    return item

    # Fallback to local keyword-overlap matching
    for item in recent_items:
        # 1. Compare titles
        title_sim = overlap_coefficient(new_title, item['title'])
        if title_sim >= similarity_threshold:
            return item
            
        # 2. Compare summaries
        old_summary = item.get('summary')
        if new_summary and old_summary:
            summary_sim = overlap_coefficient(new_summary, old_summary)
            if summary_sim >= summary_threshold:
                return item
            
    return None
