# ShadowMod 

ShadowMod is a Discord moderation bot designed to help server moderators detect, investigate, and manage suspicious user activity in real time.
It uses rule-based message scoring and moderation tools to assist human moderators without replacing them.

---

## Features

- Suspicious message detection using spam heuristics  
- Configurable alert thresholds per server  
- Moderator alert channel support  
- User investigation with recent messages and risk analysis  
- Warning, timeout (role-based), purge, and ban commands  
- Watchlist support for monitoring specific users  
- Persistent storage using JSON  

---

## Tech Stack

- Python 3.10+
- discord.py (v2+)
- aiohttp
- python-dotenv

---

## Setup

### Install dependencies

#Environment variable

Create a .env file locally
BOT_TOKEN=your_discord_bot_token

#Run the bot

python bot.py

#Deployment

This project includes a Procfile for deployment on platforms like Render, Railway, or Heroku-style services.
worker: python bot.py

#Required Permissions

- View Channels
- Send Messages
- Read Message History
- Manage Messages
- Moderate Members
- Manage Roles (for timeout feature)
- The bot role must be above moderated user roles.

#Notes

- Uses rule-based heuristics, not machine learning
- Designed for educational and personal use




