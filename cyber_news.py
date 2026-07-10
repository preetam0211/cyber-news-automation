#!/usr/bin/env python3
import os
import sys
import re
import json
import html
import logging
import argparse
import time
from datetime import datetime, timedelta, timezone
import requests
import feedparser
from dotenv import load_dotenv

# Ensure standard streams use UTF-8 on Windows to handle emojis correctly
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

DEFAULT_HN_FEED = "https://thehackernews.com/feeds/posts/default"
DEFAULT_BC_FEED = "https://www.bleepingcomputer.com/feed/"
DEFAULT_DB_NAME = "seen_items.json"

STOP_WORDS = {
    'a', 'an', 'the', 'in', 'on', 'to', 'for', 'of', 'and', 'or', 'is', 'are', 
    'with', 'by', 'from', 'at', 'about', 'as', 'into', 'that', 'this', 'these', 
    'those', 'it', 'its', 'new', 'how', 'why', 'what', 'who', 'which', 'was', 
    'were', 'be', 'been', 'has', 'have', 'had', 'to', 'from', 'over', 'out', 'up'
}

def load_seen_items(db_path):
    """Load seen items from JSON file."""
    if not os.path.exists(db_path):
        logger.info(f"Database file {db_path} not found. Creating a new one.")
        return []
    try:
        with open(db_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            if isinstance(data, list):
                return data
            logger.warning("Database format is not a list. Initializing empty list.")
            return []
    except Exception as e:
        logger.error(f"Error reading database {db_path}: {e}. Initializing empty list.")
        return []

def save_seen_items(db_path, items):
    """Save seen items to JSON file with indentation for clean git diffs."""
    try:
        with open(db_path, 'w', encoding='utf-8') as f:
            json.dump(items, f, ensure_ascii=False, indent=2)
    except Exception as e:
        logger.error(f"Error saving database {db_path}: {e}")

def tokenize(title):
    """Tokenize a title into lowercase words, removing stop words and short elements."""
    if not title:
        return set()
    # Find all words/alphanumeric strings
    words = re.findall(r'\b\w+\b', title.lower())
    # Filter out stop words, digits, and short tokens
    tokens = {w for w in words if w not in STOP_WORDS and len(w) > 2 and not w.isdigit()}
    return tokens

def overlap_coefficient(title1, title2):
    """Calculate the Overlap Coefficient between two titles."""
    tokens1 = tokenize(title1)
    tokens2 = tokenize(title2)
    
    if not tokens1 or not tokens2:
        return 0.0
        
    intersection = tokens1.intersection(tokens2)
    return len(intersection) / min(len(tokens1), len(tokens2))

def is_duplicate(new_title, seen_items, days_limit=5, similarity_threshold=0.65):
    """Check if new_title is very similar to any article posted in the last days_limit days."""
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
        similarity = overlap_coefficient(new_title, item['title'])
        if similarity >= similarity_threshold:
            return item
            
    return None

def clean_html(raw_html):
    """Remove HTML tags and escape special characters to make text safe for Telegram HTML parse mode."""
    if not raw_html:
        return ""
    # Strip HTML tags
    clean_text = re.sub(r'<[^>]+>', '', raw_html)
    # Escape &, <, > characters for Telegram HTML parse mode
    return html.escape(clean_text).strip()

def format_telegram_message(entry, source):
    """Format a feed entry into a Telegram HTML message."""
    title = clean_html(entry.get('title', 'No Title'))
    link = html.escape(entry.get('link', ''))
    published = clean_html(entry.get('published', 'No Date'))
    
    # Handle summary/description parsing
    summary_raw = entry.get('summary', '') or entry.get('description', '')
    summary = clean_html(summary_raw)
    
    # Truncate summary if it's too long
    max_summary_length = 400
    if len(summary) > max_summary_length:
        summary = summary[:max_summary_length] + "..."

    emoji = "🛡️" if "hacker" in source.lower() else "💻"
    
    message = (
        f"<b>{emoji} {source} News</b>\n\n"
        f"<b>Title:</b> {title}\n"
        f"<b>Date:</b> {published}\n\n"
        f"<b>Summary:</b>\n{summary}\n\n"
        f"🔗 <a href='{link}'>Read full article</a>"
    )
    return message

def send_telegram_message(token, chat_id, text, thread_id=None, retries=3):
    """Send an HTML-formatted message to Telegram with retry logic and rate limit handling."""
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": False
    }
    if thread_id is not None:
        payload["message_thread_id"] = thread_id
        
    for attempt in range(retries):
        try:
            response = requests.post(url, json=payload, timeout=15)
            
            # Handle rate limiting (429)
            if response.status_code == 429:
                try:
                    retry_after = response.json().get("parameters", {}).get("retry_after", 10)
                except Exception:
                    retry_after = 10
                logger.warning(f"Telegram Rate Limit exceeded (429). Sleeping for {retry_after} seconds before retry...")
                time.sleep(retry_after)
                continue
                
            response.raise_for_status()
            return True
            
        except requests.exceptions.HTTPError as http_err:
            logger.error(f"HTTP error occurred while sending message to Telegram (Attempt {attempt + 1}/{retries}): {http_err} - Response: {response.text}")
            # If it's a 400 Bad Request, retrying won't help (formatting/chat-id error), so return False immediately
            if response.status_code == 400:
                return False
        except Exception as err:
            logger.error(f"Error occurred while sending message to Telegram (Attempt {attempt + 1}/{retries}): {err}")
            
        if attempt < retries - 1:
            time.sleep(2)
            
    return False

def prune_old_items(items, days_limit=30):
    """Remove items that are older than days_limit days to keep the database size small."""
    now = datetime.now(timezone.utc)
    pruned_items = []
    pruned_count = 0
    
    for item in items:
        created_at_str = item.get('created_at')
        if not created_at_str:
            pruned_items.append(item)
            continue
        try:
            created_at = datetime.fromisoformat(created_at_str)
            if created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=timezone.utc)
            if now - created_at <= timedelta(days=days_limit):
                pruned_items.append(item)
            else:
                pruned_count += 1
        except Exception:
            pruned_items.append(item)
            
    if pruned_count > 0:
        logger.info(f"Pruned {pruned_count} seen items older than {days_limit} days.")
    return pruned_items

def fetch_feed_with_retry(url, name, retries=3, delay=2):
    """Fetch feed content with retry mechanism and a browser-like User-Agent to bypass WAF blocks."""
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "application/rss+xml, application/rdf+xml, application/atom+xml, application/xml, text/xml"
    }
    
    for attempt in range(retries):
        try:
            logger.info(f"Fetching RSS feed for {name} (Attempt {attempt + 1}/{retries}): {url}")
            response = requests.get(url, headers=headers, timeout=20)
            response.raise_for_status()
            
            feed = feedparser.parse(response.content)
            return feed
        except Exception as e:
            logger.warning(f"Attempt {attempt + 1} failed to fetch feed from {url}: {e}")
            if attempt < retries - 1:
                time.sleep(delay * (2 ** attempt))
            else:
                logger.error(f"All attempts failed to fetch feed for {name} from {url}")
                
    # Fallback to direct feedparser fetch
    logger.info(f"Attempting fallback direct feedparser fetch for {name}...")
    try:
        return feedparser.parse(url)
    except Exception as fallback_err:
        logger.error(f"Fallback direct fetch failed for {name}: {fallback_err}")
        return None

def parse_args():
    parser = argparse.ArgumentParser(description="Cybersecurity News Telegram Notifier with Deduplication")
    parser.add_argument(
        '--dry-run', 
        action='store_true', 
        help="Fetch, format, and deduplicate new items but do not send them to Telegram or save them to seen items."
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help="Enable debug logging output."
    )
    return parser.parse_args()

def main():
    args = parse_args()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        
    # Load configuration
    load_dotenv()
    
    hn_feed_url = os.getenv("HACKER_NEWS_FEED_URL") or DEFAULT_HN_FEED
    bc_feed_url = os.getenv("BLEEPING_COMPUTER_FEED_URL") or DEFAULT_BC_FEED
    db_path = os.getenv("DB_PATH") or DEFAULT_DB_NAME
    
    telegram_token = os.getenv("TELEGRAM_BOT_TOKEN")
    telegram_chat_id = os.getenv("TELEGRAM_CHAT_ID")
    
    thread_id = os.getenv("TELEGRAM_TOPIC_ID")
    if thread_id and thread_id.strip():
        try:
            thread_id = int(thread_id.strip())
        except ValueError:
            logger.warning(f"Invalid Topic/Thread ID mapping '{thread_id}'. Ignoring.")
            thread_id = None

    if not args.dry_run:
        if not telegram_token or not telegram_chat_id:
            logger.error("Configuration Error: TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID must be set in environment or .env file.")
            logger.info("Use --dry-run option to run the script without Telegram credentials.")
            sys.exit(1)
            
    # Load seen database
    seen_items = load_seen_items(db_path)
    seen_guids = {item['guid'] for item in seen_items if 'guid' in item}
    
    feeds_to_process = [
        {"url": hn_feed_url, "name": "The Hacker News"},
        {"url": bc_feed_url, "name": "BleepingComputer"}
    ]
    
    new_entries_to_process = []
    
    # Fetch feeds
    for feed_info in feeds_to_process:
        feed = fetch_feed_with_retry(feed_info['url'], feed_info['name'])
        if not feed or not feed.entries:
            logger.warning(f"No entries found in the RSS feed for {feed_info['name']}.")
            continue
            
        logger.info(f"Found {len(feed.entries)} entries in {feed_info['name']} feed.")
        for entry in feed.entries:
            guid = entry.get('id') or entry.get('guid') or entry.get('link')
            if not guid:
                continue
            entry['source_site'] = feed_info['name']
            new_entries_to_process.append((guid, entry))

    # Order chronologically (oldest first)
    def get_published_time(item_tuple):
        _, entry = item_tuple
        if hasattr(entry, 'published_parsed') and entry.published_parsed:
            return entry.published_parsed
        return entry.get('published', '')

    try:
        new_entries_to_process.sort(key=get_published_time)
    except Exception as e:
        logger.warning(f"Could not sort entries chronologically: {e}. Falling back to default order.")
        new_entries_to_process.reverse()

    new_entries_count = 0
    sent_count = 0
    skipped_duplicates = 0
    
    updated_items = list(seen_items)
    
    for guid, entry in new_entries_to_process:
        try:
            source_site = entry['source_site']
            title = entry.get('title', 'No Title')
            link = entry.get('link', '')
            published = entry.get('published', 'No Date')
            
            # Check if already processed GUID
            if guid in seen_guids:
                continue
                
            # Check duplicate based on content similarity
            duplicate_item = is_duplicate(title, updated_items)
            if duplicate_item:
                skipped_duplicates += 1
                logger.info(f"[DUPLICATE] Skipping: \"{title}\" ({source_site}) is similar to already posted: \"{duplicate_item['title']}\" ({duplicate_item['source']})")
                
                # Still mark as seen to avoid processing it again next run
                new_item = {
                    "guid": guid,
                    "title": title,
                    "link": link,
                    "published": published,
                    "source": source_site,
                    "created_at": datetime.now(timezone.utc).isoformat()
                }
                updated_items.append(new_item)
                seen_guids.add(guid)
                continue
                
            new_entries_count += 1
            message_text = format_telegram_message(entry, source_site)
            
            if args.dry_run:
                logger.info(f"[DRY-RUN] Would send message to Telegram:\n{message_text}\n" + "-"*40)
                new_item = {
                    "guid": guid,
                    "title": title,
                    "link": link,
                    "published": published,
                    "source": source_site,
                    "created_at": datetime.now(timezone.utc).isoformat()
                }
                updated_items.append(new_item)
                seen_guids.add(guid)
            else:
                logger.info(f"Sending notification to Telegram: {title} ({source_site})...")
                success = send_telegram_message(telegram_token, telegram_chat_id, message_text, thread_id)
                if success:
                    new_item = {
                        "guid": guid,
                        "title": title,
                        "link": link,
                        "published": published,
                        "source": source_site,
                        "created_at": datetime.now(timezone.utc).isoformat()
                    }
                    updated_items.append(new_item)
                    seen_guids.add(guid)
                    sent_count += 1
                    logger.info("Message sent successfully.")
                    
                    # Sleep 1.2s to respect Telegram single-chat rate limits (20 messages/min)
                    time.sleep(1.2)
                else:
                    logger.error(f"Failed to send announcement after retries: {title}. Will retry next run.")
                    
        except Exception as entry_err:
            logger.error(f"Unexpected error processing entry \"{entry.get('title', 'No Title')}\": {entry_err}")
            continue

    if not args.dry_run:
        # Prune old database entries and save changes
        pruned_items = prune_old_items(updated_items, days_limit=30)
        save_seen_items(db_path, pruned_items)
        
    logger.info(f"Scan complete. New entries detected: {new_entries_count}. Successfully sent: {sent_count}. Skipped duplicates: {skipped_duplicates}.")

if __name__ == "__main__":
    main()
