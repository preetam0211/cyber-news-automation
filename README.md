# ⚡ Hybrid Serverless Cyber Threat Intelligence Feed Notifier

A high-precision, zero-cost, and low-latency cybersecurity threat feed that aggregates RSS feeds from major portals, maps threat articles to security frameworks, and broadcasts deduplicated alerts directly to Telegram.

This system runs **completely free** by combining **AWS EventBridge** and **GitHub Actions** in a stateless, hybrid-serverless GitOps architecture.

---

## 🏗️ System Architecture

![System Architecture](threat_feed_architecture.jpg)

### Execution Flow:
1. **AWS EventBridge** triggers a cron schedule twice an hour and invokes the GitHub Actions workflow via the `workflow_dispatch` API to bypass runner scheduling queues.
2. **GitHub Actions** provisions a stateless Linux runner.
3. The **Python Pipeline** pulls feed data from *The Hacker News*, *BleepingComputer*, and *CybersecurityNews*.
4. **Resilient Scrapers** execute a browser-emulated request (or fall back to feedparser) to bypass Cloudflare WAF `403` blocks.
5. **Deduplication Engine** checks for duplicates by tokenizing content and running an Overlap Coefficient comparison.
6. **Threat Framework Mapper** maps standard threats to **MITRE ATT&CK** and AI-related threats to **MITRE ATLAS** using a high-performance local regex classifier.
7. **Telegram Broadcast** formats, HTML-escapes, rate-limits, and sends notifications.
8. **GitOps Database** commits the updated `seen_items.json` state back to the repository.

---

## 🚀 Key Engineering Challenges & Solutions

### 1. Dual-Factor Content Deduplication 🔄
* **Challenge**: News portals often write completely different headlines for the same vulnerability, making basic string-matching ineffective.
* **Solution**: Developed a dual-factor engine:
  * **Tokenized Overlap Check**: Tokenizes titles and summaries, filters stopwords, processes 2-letter tokens (like `AI`, `C2`, `IP`), and calculates the Overlap Coefficient.
  * **Dual checks**: It compares titles (threshold `0.58`) **and** detailed summaries (threshold `0.60`). If either matches, it is flagged as a duplicate.

### 2. Multi-Framework Threat Mapping (MITRE ATT&CK + ATLAS) 🎯
* **Challenge**: Dynamically classifying threat alerts into standard enterprise tactics (MITRE ATT&CK) vs. artificial intelligence threat landscapes (MITRE ATLAS) without calling external API services.
* **Solution**: Built a local regex mapping module (`mitre_map.py`) that extracts security keywords (phishing, exploits, ransomware) and maps them to their parent Tactic and Technique. It scans for AI-specific keywords to swap frameworks dynamically, and includes a title-based filter to bypass mapping for weekly summaries and newsletters.

### 3. Defeating WAF Blocks 🛡️
* **Challenge**: Cloudflare WAF blocks cloud provider IP ranges (including GitHub Action runners), resulting in `403 Forbidden` errors.
* **Solution**: Implemented a browser-simulated scraper utilizing modern Chrome headers. If the request is still blocked, the pipeline automatically falls back to direct XML parsing.

### 4. Database State on Stateless Runners 💾
* **Challenge**: GitHub Action runners are destroyed after each run, leaving no persistent disk storage. Committing SQLite binaries causes dirty repository histories.
* **Solution**: Structured a GitOps-driven JSON database (`seen_items.json`). The database stores hashed identifiers and article summaries for the rolling 5-day window. Entries older than 30 days are automatically pruned, and changes are pushed back to GitHub with auto-retry logic to handle transient `503` network issues.

---

## 🛠️ Installation & Local Setup

### Prerequisites
* Python 3.10+
* A Telegram Bot token (from [@BotFather](https://t.me/BotFather)) and Chat ID.

### Setup Steps
1. Clone this repository:
   ```bash
   git clone https://github.com/preetam0211/cyber-news-automation.git
   cd cyber-news-automation
   ```
2. Create and activate a virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Copy the environment template and fill in your values:
   ```bash
   cp .env.example .env
   ```
5. Run the local test suite:
   ```bash
   python verify_dedup.py
   python verify_mitre.py
   ```
6. Run the script manually:
   ```bash
   python cyber_news.py
   ```

---

## ⚙️ GitHub Actions Deployment

To run this feed autonomously, add the following secrets to your GitHub repository (**Settings > Secrets and variables > Actions**):

| Secret Name | Description |
|---|---|
| `TELEGRAM_BOT_TOKEN` | Token for your Telegram Bot |
| `TELEGRAM_CHAT_ID` | Telegram Channel or Group ID |

---

## 📄 License

All Rights Reserved. This codebase is made public strictly for portfolio demonstration. Unauthorized copying, modification, or distribution is prohibited.
