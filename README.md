ShadowMod — Discord Moderation Bot

ShadowMod is a rule-based Discord moderation bot designed to detect and respond to harmful or disruptive behavior in real time. Instead of relying solely on static keyword blocking, ShadowMod uses a risk scoring system that evaluates message patterns, repetition, and content signals to assist moderators in maintaining healthy communities.

The project focuses on event-driven backend logic, moderation workflows, and persistent state handling using Python and discord.py.


---

📌 Project Overview

ShadowMod is implemented as a single Python service built around Discord’s gateway events and slash commands.

The bot:

• Listens to real-time message events

• Analyzes content using regex-based heuristics

• Assigns dynamic risk scores to users based on behavior

• Tracks infractions persistently across restarts

• Provides moderation tools via slash commands

• Sends alerts when configurable thresholds are crossed


The system is designed to assist human moderators, not replace them.


---

🧠 Motivation

Many moderation bots rely on rigid word filters that lack context.

Real moderation requires:

• Pattern recognition over time

• Escalation based on repetition

• Human oversight and control


This project explores how lightweight scoring systems can:

• Reduce spam and low-effort abuse

• Flag problematic behavior early

• Preserve moderator authority



---

🛠️ Tech Stack

• Language: Python 3

• Library: discord.py (v2+)


Concepts used:

• Asynchronous programming (asyncio)

• Event-driven architecture

• Slash commands (app_commands)

• Permission and role checks

• Regex-based text analysis

• Persistent storage using JSON

• Environment variable configuration



---

📂 Project Structure

```
shadowmod/
├── bot.py                  # Main bot logic and event handlers
├── shadowmod_config.json   # Persistent moderation configuration
├── requirements.txt        # Python dependencies
├── Procfile                # Deployment entrypoint
├── .gitignore
└── README.md
```

---

⚙️ Configuration

ShadowMod requires a Discord bot token to be set as an environment variable.
```
BOT_TOKEN=your_discord_bot_token_here
```

---

▶️ How to Run Locally

Install dependencies
```
pip install -r requirements.txt
```
Set bot token

Windows (PowerShell):
```
set BOT_TOKEN=your_token_here
```
macOS / Linux:
```
export BOT_TOKEN=your_token_here
```
Run the bot
```
python bot.py
```

---

🔧 Core Features

• Real-time message monitoring

• Risk-based user scoring system

• Configurable alert thresholds

• Persistent infraction tracking

• Role-aware moderation controls

• Slash command interface

• Moderator alert notifications



---

🚧 Current Limitations

• Heuristic rules only (no machine learning)

• JSON storage instead of a database

• Single-file architecture

• No automated tests yet



---

🔮 Possible Improvements

• Modularize logic into cogs

• Replace JSON with SQLite or PostgreSQL

• Add structured logging and analytics

• Introduce ML-based classification

• Add CI and automated testing

• Dockerize for deployment


---

👤 Author

Parth Sinha 
GitHub:
https://github.com/parthsinha2006

Anshika Bisht
GitHub: https://github.com/AnshikaBisht1202


---

⭐ Why This Project Matters

This project demonstrates:

• Practical backend problem-solving

• Asynchronous Python programming

• Real-world moderation workflows

• State persistence and configuration management


ShadowMod is not just a bot that runs — it is a system that models real moderation logic used in live communities.
