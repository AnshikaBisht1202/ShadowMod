# bot.py - ShadowMod (full)
# Requirements: discord.py v2+, python-dotenv (optional)
# Run: set BOT_TOKEN env var and `python3 bot.py`

import os
import re
import json
import datetime
import asyncio
from collections import deque, defaultdict

import discord
from discord.ext import commands
from discord import app_commands

# Optional: use a .env file for BOT_TOKEN (uncomment if you use it)
# from dotenv import load_dotenv
# load_dotenv()

# -------------------------
# CONFIG
# -------------------------
BOT_TOKEN = os.environ.get("BOT_TOKEN")
CONFIG_FILE = "shadowmod_config.json"
RECENT_MSG_LIMIT = 2000
RECENT_PER_USER = 50
DEFAULT_ALERT_THRESHOLD = 60

# -------------------------
# INTENTS & BOT SETUP
# -------------------------
intents = discord.Intents.default()
intents.message_content = True
intents.members = True

bot = commands.Bot(command_prefix="!", intents=intents)

# -------------------------
# RUNTIME STORES
# -------------------------
recent_messages = defaultdict(lambda: deque(maxlen=RECENT_MSG_LIMIT))  # guild_id -> deque of messages
mod_alert_channel = {}            # guild_id -> channel_id
user_infractions = defaultdict(list)  # user_id -> list of (iso_ts, reason)
alert_threshold = {}              # guild_id -> int
watchlist = defaultdict(set)      # guild_id -> set(user_id)

load_lock = asyncio.Lock()

# Simple rules configuration
SHORT_URL_RE = re.compile(r'\b(?:bit\.ly|t\.co|tinyurl\.com|goo\.gl|ow\.ly|tinyurl)\b', flags=re.IGNORECASE)
HTTP_RE = re.compile(r'http[s]?://', flags=re.IGNORECASE)
SPAM_KEYWORDS = ["free nitro", "claim now", "giveaway", "join my", "earn money", "click here"]

# -------------------------
# Persistence
# -------------------------
def _load_config():
    global mod_alert_channel, user_infractions, alert_threshold, watchlist
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        mod_alert_channel = {int(k): int(v) for k, v in data.get("mod_alert_channel", {}).items()}
        ui = data.get("user_infractions", {})
        user_infractions.clear()
        for k, v in ui.items():
            user_infractions[int(k)] = v
        at = data.get("alert_threshold", {})
        alert_threshold = {int(k): int(v) for k, v in at.items()}
        wl = data.get("watchlist", {})
        watchlist.clear()
        for gid, users in wl.items():
            try:
                watchlist[int(gid)] = set(int(u) for u in users)
            except Exception:
                watchlist[int(gid)] = set()
        print(f"[CONFIG] Loaded config from {CONFIG_FILE}")
    except FileNotFoundError:
        print("[CONFIG] No config file found — starting fresh.")
    except Exception as e:
        print("[CONFIG] Failed to load config:", repr(e))

async def _save_config_async():
    async with load_lock:
        try:
            data = {
                "mod_alert_channel": {str(k): v for k, v in mod_alert_channel.items()},
                "user_infractions": {str(k): v for k, v in user_infractions.items()},
                "alert_threshold": {str(k): v for k, v in alert_threshold.items()},
                "watchlist": {str(k): list(v) for k, v in watchlist.items()}
            }
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            print(f"[CONFIG] Saved config to {CONFIG_FILE}")
        except Exception as e:
            print("[CONFIG] Failed to save config:", repr(e))

# -------------------------
# Scoring
# -------------------------
def score_message_and_get_reasons(message_text: str):
    score = 0
    reasons = []
    if not message_text:
        return 0, []
    link_count = len(HTTP_RE.findall(message_text))
    if link_count >= 2:
        score += 30
        reasons.append("multiple_links")
    if SHORT_URL_RE.search(message_text):
        score += 35
        reasons.append("short_url")
    if re.search(r'([!?.]){4,}|([a-zA-Z])\1{8,}', message_text):
        score += 10
        reasons.append("repeated_chars")
    lowered = message_text.lower()
    for kw in SPAM_KEYWORDS:
        if kw in lowered:
            score += 25
            reasons.append(f"keyword:{kw}")
    score = max(0, min(100, score))
    return score, reasons

# -------------------------
# Events
# -------------------------
@bot.event
async def on_ready():
    _load_config()
    print(f"[READY] Logged in as {bot.user} (ID: {bot.user.id})")
    try:
        synced = await bot.tree.sync()
        print(f"[READY] Synced {len(synced)} global commands.")
    except Exception as e:
        print("[READY] Command sync failed:", repr(e))

@bot.event
async def on_message(message: discord.Message):
    # ignore bots
    if message.author.bot:
        return

    guild = message.guild
    guild_id = guild.id if guild else None

    # store message
    recent_messages[guild_id].append({
        "user_id": message.author.id,
        "channel_id": message.channel.id,
        "content": message.content,
        "created_at": message.created_at.isoformat(),
        "message_id": message.id
    })

    # score
    score, reasons = score_message_and_get_reasons(message.content)

    # per-guild threshold & watchlist handling
    server_threshold = alert_threshold.get(guild_id, DEFAULT_ALERT_THRESHOLD)
    is_watched = guild_id in watchlist and message.author.id in watchlist[guild_id]

    # If message is suspicious or user is on watchlist -> alert
    if (score >= server_threshold or is_watched) and guild_id is not None:
        alert_text = (
            f"⚠️ **Suspicious activity detected**\n"
            f"Server: **{guild.name}** (ID: {guild.id})\n"
            f"User: {message.author} — `{message.author.id}`\n"
            f"Score: {score}/100\n"
            f"Reasons: {', '.join(reasons) if reasons else 'none'}\n"
            f"Message preview: {message.content[:400]!s}"
        )

        alerted = 0

        # Try configured mod channel
        if guild_id in mod_alert_channel:
            ch_id = int(mod_alert_channel[guild_id])
            ch = bot.get_channel(ch_id)
            if ch is None:
                try:
                    ch = await bot.fetch_channel(ch_id)
                    print(f"[ALERT] Fetched channel object for id {ch_id}")
                except Exception as e:
                    print(f"[ALERT] Could not fetch channel {ch_id}: {repr(e)}")
                    ch = None

            if ch:
                try:
                    bot_member = guild.get_member(bot.user.id)
                    perms = ch.permissions_for(bot_member) if bot_member else ch.permissions_for(guild.me or bot.user)
                    if not perms.send_messages:
                        print(f"[ALERT] Bot lacks send_messages in channel {ch_id}. Permissions: {perms}")
                    else:
                        await ch.send(alert_text)
                        alerted = 1
                        print(f"[ALERT] Sent alert to configured channel {ch_id} in guild {guild_id}")
                except Exception as e:
                    print(f"[ALERT] Failed to send to channel {ch_id}: {repr(e)}")

        # Fallback: DM mods
        if alerted == 0 and guild:
            dm_count = 0
            for member in guild.members:
                if member.guild_permissions.manage_messages:
                    try:
                        await member.send(alert_text)
                        dm_count += 1
                    except Exception as e:
                        print(f"[ALERT] Could not DM {member} ({member.id}): {repr(e)}")
            alerted = dm_count

        print(f"[ALERT] Alerting complete. alerted={alerted} (guild {guild_id})")

    await bot.process_commands(message)  # allow prefix commands if later added

# -------------------------
# Slash commands
# -------------------------
@bot.tree.command(name="checkperm", description="Check whether you have Manage Messages permission.")
async def checkperm(interaction: discord.Interaction):
    has_perm = interaction.user.guild_permissions.manage_messages
    if has_perm:
        await interaction.response.send_message("✅ You DO have Manage Messages permission.", ephemeral=True)
    else:
        await interaction.response.send_message("❌ You do NOT have Manage Messages permission.", ephemeral=True)

@bot.tree.command(name="set_mod_channel", description="Set the channel where moderation alerts will be posted.")
@app_commands.describe(channel="The channel to receive moderation alerts")
async def set_mod_channel(interaction: discord.Interaction, channel: discord.TextChannel):
    if not interaction.user.guild_permissions.manage_messages:
        await interaction.response.send_message("❌ You need Manage Messages permission to use this.", ephemeral=True)
        return
    mod_alert_channel[interaction.guild_id] = channel.id
    await _save_config_async()
    await interaction.response.send_message(f"✅ Mod alert channel set to {channel.mention}", ephemeral=True)

@bot.tree.command(name="force_alert", description="Force-send a test moderation alert to configured channel.")
@app_commands.describe(user="User to include in test alert")
async def force_alert(interaction: discord.Interaction, user: discord.Member):
    if not interaction.user.guild_permissions.manage_messages:
        await interaction.response.send_message("❌ You need Manage Messages permission.", ephemeral=True)
        return
    gid = interaction.guild_id
    if gid not in mod_alert_channel:
        await interaction.response.send_message("No mod alert channel configured for this server.", ephemeral=True)
        return
    ch_id = int(mod_alert_channel[gid])
    await interaction.response.send_message(f"Attempting to send test alert to channel id `{ch_id}`...", ephemeral=True)
    ch = bot.get_channel(ch_id)
    if ch is None:
        try:
            ch = await bot.fetch_channel(ch_id)
            print(f"[FORCE] Fetched channel object for id {ch_id}")
        except Exception as e:
            print(f"[FORCE] Could not fetch channel {ch_id}: {repr(e)}")
            return
    try:
        bot_member = interaction.guild.get_member(bot.user.id)
        perms = ch.permissions_for(bot_member) if bot_member else ch.permissions_for(interaction.guild.me or bot.user)
        if not perms.send_messages:
            print(f"[FORCE] Bot lacks send_messages in channel {ch_id}. Permissions: {perms}")
            await interaction.followup.send("Bot lacks permission to send in the configured channel. Check channel permissions.", ephemeral=True)
            return
        await ch.send(f"🧪 Forced test alert for {user.mention} by {interaction.user.mention}")
        print(f"[FORCE] Successfully sent forced alert to channel {ch_id}")
    except Exception as e:
        print(f"[FORCE] Failed to send forced alert to {ch_id}: {repr(e)}")

@bot.tree.command(name="add_infraction", description="Record an infraction for a user.")
@app_commands.describe(user="User to add infraction for", reason="Short description")
async def add_infraction(interaction: discord.Interaction, user: discord.Member, reason: str):
    # permission check
    if not interaction.user.guild_permissions.manage_messages:
        await interaction.response.send_message("❌ You need Manage Messages permission.", ephemeral=True)
        return

    # quick response guard (not strictly necessary here, but safe)
    await interaction.response.defer(ephemeral=True)

    try:
        # correct timestamp
        ts = datetime.datetime.utcnow().isoformat()
        user_infractions[user.id].append((ts, reason))
        await _save_config_async()

        # send confirmation
        await interaction.followup.send(f"✅ Infraction recorded for {user.mention}", ephemeral=True)

    except Exception as e:
        # log full traceback to terminal for debugging
        import traceback
        print("[ADD_INFRACTION] Exception:", repr(e))
        traceback.print_exc()
        # let the moderator know something went wrong
        try:
            await interaction.followup.send("⚠️ Failed to record infraction — check bot logs.", ephemeral=True)
        except Exception:
            try:
                await interaction.response.send_message("⚠️ Failed to record infraction.", ephemeral=True)
            except Exception:
                pass


@bot.tree.command(name="set_threshold", description="Set alert threshold for this server (0-100).")
@app_commands.describe(value="threshold value")
async def set_threshold(interaction: discord.Interaction, value: int):
    if not interaction.user.guild_permissions.manage_messages:
        await interaction.response.send_message("❌ You need Manage Messages permission.", ephemeral=True)
        return
    if value < 0 or value > 100:
        await interaction.response.send_message("Value must be between 0 and 100.", ephemeral=True)
        return
    alert_threshold[interaction.guild_id] = int(value)
    await _save_config_async()
    await interaction.response.send_message(f"✅ Alert threshold set to {value}.", ephemeral=True)

@bot.tree.command(name="investigate", description="Investigate a user's recent messages and aggregated risk.")
@app_commands.describe(user="User to investigate")
async def investigate(interaction: discord.Interaction, user: discord.Member):
    # permission guard
    if not interaction.user.guild_permissions.manage_messages:
        await interaction.response.send_message("❌ You need Manage Messages permission to use this.", ephemeral=True)
        return

    # Defer to buy time (so Discord doesn't show "did not respond")
    await interaction.response.defer(ephemeral=True)

    try:
        gid = interaction.guild_id
        # gather messages
        msgs = [m for m in recent_messages.get(gid, []) if m["user_id"] == user.id]
        last_msgs = msgs[-RECENT_PER_USER:]

        # aggregate rule-based score
        agg_score = 0
        agg_reasons = []
        for m in last_msgs:
            s, r = score_message_and_get_reasons(m.get("content") or "")
            agg_score = min(100, agg_score + s)
            agg_reasons.extend(r)

        uniq_reasons = sorted(set(agg_reasons))

        # build embed (note correct datetime usage)
        import datetime as _dt
        embed = discord.Embed(
            title=f"Investigation — {user}",
            description=f"Aggregated risk: {agg_score}/100 — Recent messages: {len(last_msgs)}",
            color=discord.Color.orange(),
            timestamp=_dt.datetime.utcnow()
        )

        embed.add_field(name="Top reasons", value=", ".join(uniq_reasons) if uniq_reasons else "No rule matches detected", inline=False)

        preview_texts = []
        for m in last_msgs[-6:]:
            ch = bot.get_channel(m["channel_id"])
            ch_name = ch.name if ch else f"#{m['channel_id']}"
            ts = m["created_at"]
            preview_texts.append(f"[{ch_name}] {ts} — {m.get('content','')[:200]}")
        embed.add_field(name="Latest messages", value="\n".join(preview_texts) or "No recent messages", inline=False)

        infra = user_infractions.get(user.id, [])
        infra_text = "\n".join(f"{t} — {r}" for t, r in infra[-6:]) if infra else "No infractions recorded"
        embed.add_field(name="Infractions (recent)", value=infra_text, inline=False)

        embed.set_footer(text="Use Discord moderation actions after reviewing this context.")

        # send the embed (we already deferred)
        await interaction.followup.send(embed=embed, ephemeral=True)

    except Exception as e:
        # log full traceback so you can paste it if you need help
        import traceback
        print("[INVESTIGATE] Exception:", repr(e))
        traceback.print_exc()
        # give a friendly ephemeral error to the moderator
        try:
            await interaction.followup.send("⚠️ An error occurred while running /investigate. Check the bot logs.", ephemeral=True)
        except Exception:
            # if followup fails, try a plain response (best-effort)
            try:
                await interaction.response.send_message("⚠️ An error occurred (and followup failed).", ephemeral=True)
            except Exception:
                pass


# Moderation commands
@bot.tree.command(name="purge", description="Purge (delete) up to N recent messages from this channel.")
@app_commands.describe(amount="Number of messages to delete (max 100)")
async def purge(interaction: discord.Interaction, amount: int):
    if not interaction.user.guild_permissions.manage_messages:
        await interaction.response.send_message("You need Manage Messages permission.", ephemeral=True)
        return
    if amount < 1 or amount > 100:
        await interaction.response.send_message("Amount must be between 1 and 100.", ephemeral=True)
        return
    await interaction.response.send_message(f"Purging {amount} messages...", ephemeral=True)
    try:
        deleted = await interaction.channel.purge(limit=amount)
        await interaction.followup.send(f"✅ Deleted {len(deleted)} messages.", ephemeral=True)
    except Exception as e:
        await interaction.followup.send(f"Failed to purge: {repr(e)}", ephemeral=True)

@bot.tree.command(name="ban", description="Ban a user from the server.")
@app_commands.describe(user="User to ban", reason="Reason (optional)")
async def ban(interaction: discord.Interaction, user: discord.Member, reason: str = None):

    # Caller permission check
    if not interaction.user.guild_permissions.ban_members:
        await interaction.response.send_message("❌ You need Ban Members permission.", ephemeral=True)
        return

    await interaction.response.defer(ephemeral=True)

    guild = interaction.guild
    bot_member = guild.get_member(bot.user.id)

    # Target cannot be owner
    if user == guild.owner:
        await interaction.followup.send("❌ Cannot ban the server owner.", ephemeral=True)
        return

    # Bot must have ban_members
    if not bot_member.guild_permissions.ban_members:
        await interaction.followup.send(
            "❌ I do not have the **Ban Members** permission. Give me this permission in Roles settings.",
            ephemeral=True
        )
        return

    # Check bannable
    try:
        if hasattr(user, "bannable") and not user.bannable:
            await interaction.followup.send(
                "❌ I cannot ban this user — my role is not high enough.",
                ephemeral=True
            )
            return
    except:
        pass

    try:
        # Attempt to ban
        await guild.ban(user, reason=reason or "No reason provided.")

        # CORRECT timestamp
        ts = datetime.datetime.utcnow().isoformat()

        user_infractions[user.id].append((ts, f"BANNED: {reason or 'no reason'}"))
        await _save_config_async()

        await interaction.followup.send(f"✅ Banned {user.mention}.", ephemeral=True)

    except discord.Forbidden:
        await interaction.followup.send(
            "❌ Failed to ban: Missing permissions (role hierarchy or bot permissions).",
            ephemeral=True
        )

    except Exception as e:
        import traceback
        traceback.print_exc()
        await interaction.followup.send(
            f"❌ Failed to ban due to error: {repr(e)}",
            ephemeral=True
        )


@bot.tree.command(name="warn", description="Warn a user (record an infraction).")
@app_commands.describe(user="User to warn", reason="Reason for the warning")
async def warn(interaction: discord.Interaction, user: discord.Member, reason: str):
    # permission check
    if not interaction.user.guild_permissions.manage_messages:
        await interaction.response.send_message("❌ You need Manage Messages permission.", ephemeral=True)
        return

    # defer so we have time to process
    await interaction.response.defer(ephemeral=True)

    try:
        # correct timestamp usage
        ts = datetime.datetime.utcnow().isoformat()
        user_infractions[user.id].append((ts, f"WARNING: {reason}"))
        await _save_config_async()

        # optional: DM the user (best-effort)
        try:
            await user.send(f"You have been warned on **{interaction.guild.name}**: {reason}")
        except Exception:
            # user may have DMs closed; ignore quietly
            pass

        await interaction.followup.send(f"✅ Warned {user.mention}.", ephemeral=True)

    except Exception as e:
        import traceback
        print("[WARN] Exception:", repr(e))
        traceback.print_exc()
        try:
            await interaction.followup.send("⚠️ Failed to warn the user — check bot logs.", ephemeral=True)
        except Exception:
            try:
                await interaction.response.send_message("⚠️ Failed to warn the user.", ephemeral=True)
            except Exception:
                pass


@bot.tree.command(name="timeout", description="Put a user in timeout (mute) for X minutes (role-based fallback).")
@app_commands.describe(user="User to timeout", minutes="Minutes (1 - 40320)", reason="Reason")
async def timeout(interaction: discord.Interaction, user: discord.Member, minutes: int, reason: str = None):
    # permission check
    if not interaction.user.guild_permissions.moderate_members and not interaction.user.guild_permissions.manage_messages:
        await interaction.response.send_message("❌ You need Moderate or Manage Messages permission.", ephemeral=True)
        return

    if minutes < 1 or minutes > 40320:
        await interaction.response.send_message("Minutes must be between 1 and 40320 (28 days).", ephemeral=True)
        return

    await interaction.response.defer(ephemeral=True)
    gid = interaction.guild_id
    guild = interaction.guild

    try:
        # Find or create Muted role
        muted_role = discord.utils.get(guild.roles, name="Muted")
        if muted_role is None:
            muted_role = await guild.create_role(name="Muted", reason="Created Muted role for timeout feature")
            print(f"[TIMEOUT-ROLE] Created Muted role (id={muted_role.id}) in guild {guild.id}")

        # Ensure Muted role cannot send messages in text channels (idempotent)
        for ch in guild.text_channels:
            overwrite = ch.overwrites_for(muted_role)
            changed = False
            if overwrite.send_messages is not False:
                overwrite.send_messages = False
                changed = True
            if overwrite.add_reactions is not False:
                overwrite.add_reactions = False
                changed = True
            if changed:
                try:
                    await ch.set_permissions(muted_role, overwrite=overwrite)
                except Exception as e:
                    print(f"[TIMEOUT-ROLE] Failed to set perms in channel {ch.id}: {repr(e)}")
        # Add role to user
        await user.add_roles(muted_role, reason=reason or f"Timeout by {interaction.user}")
        ts = datetime.datetime.utcnow().isoformat()
        user_infractions[user.id].append((ts, f"TIMEOUT_ROLE {minutes}m: {reason or 'no reason'}"))
        await _save_config_async()

        # Schedule unmute (non-persistent): create a background task
        async def _unmute_later(guild_id, user_id, role_id, delay_seconds):
            try:
                await asyncio.sleep(delay_seconds)
                g = bot.get_guild(guild_id)
                if not g:
                    print(f"[UNMUTE] Guild {guild_id} not found on unmute")
                    return
                member = g.get_member(user_id)
                if not member:
                    print(f"[UNMUTE] Member {user_id} not found on unmute")
                    return
                role = g.get_role(role_id)
                if not role:
                    print(f"[UNMUTE] Role {role_id} not found on unmute")
                    return
                await member.remove_roles(role, reason="Timeout expired")
                print(f"[UNMUTE] Removed Muted role from {member} ({member.id}) in guild {g.id}")
            except Exception as e:
                print(f"[UNMUTE] Exception during unmute: {repr(e)}")

        # Start background unmute
        delay = int(minutes) * 60
        asyncio.create_task(_unmute_later(guild.id, user.id, muted_role.id, delay))

        await interaction.followup.send(f"✅ Timed out {user.mention} for {minutes} minutes (role-based).", ephemeral=True)

    except Exception as e:
        import traceback
        print("[TIMEOUT-ROLE] Exception:", repr(e))
        traceback.print_exc()
        try:
            await interaction.followup.send(f"⚠️ Failed to timeout: {repr(e)}", ephemeral=True)
        except Exception:
            try:
                await interaction.response.send_message("⚠️ Failed to timeout the user.", ephemeral=True)
            except Exception:
                pass


@bot.tree.command(name="summarise", description="Summarize recent messages of a user (naive local).")
@app_commands.describe(user="User to summarize", limit="How many recent messages to include (max 200)")
async def summarise(interaction: discord.Interaction, user: discord.Member, limit: int = 50):
    if not interaction.user.guild_permissions.manage_messages:
        await interaction.response.send_message("You need Manage Messages permission.", ephemeral=True)
        return
    limit = max(1, min(200, limit))
    gid = interaction.guild_id
    msgs = [m for m in recent_messages.get(gid, []) if m["user_id"] == user.id]
    last = msgs[-limit:]
    if not last:
        await interaction.response.send_message("No recent messages to summarize.", ephemeral=True)
        return
    text = " ".join(m["content"] for m in last if m["content"])
    words = re.findall(r"\w+", text.lower())
    freq = {}
    for w in words:
        freq[w] = freq.get(w, 0) + 1
    stop = set(["the","and","is","a","to","of","in","i","you","it","that","for","on","with","this"])
    ranked_words = [w for w, _ in sorted(freq.items(), key=lambda x: -x[1]) if w not in stop][:10]
    sentences = re.split(r'(?<=[.!?])\s+', text)
    sent_scores = []
    for s in sentences:
        s_words = re.findall(r"\w+", s.lower())
        score = sum(1 for w in s_words if w in ranked_words)
        sent_scores.append((score, s))
    sent_scores.sort(reverse=True)
    summary = " ".join(s for _, s in sent_scores[:3]).strip()
    summary = (summary[:1500] + "...") if len(summary) > 1500 else summary
    await interaction.response.send_message(f"**Summary for {user.display_name}:**\n{summary}", ephemeral=True)

@bot.tree.command(name="top_spammers", description="Show top N recent message senders.")
@app_commands.describe(limit="How many users to show (max 25)")
async def top_spammers(interaction: discord.Interaction, limit: int = 10):
    if not interaction.user.guild_permissions.manage_messages:
        await interaction.response.send_message("You need Manage Messages permission.", ephemeral=True)
        return
    limit = max(1, min(25, limit))
    gid = interaction.guild_id
    counts = {}
    for m in recent_messages.get(gid, []):
        counts[m["user_id"]] = counts.get(m["user_id"], 0) + 1
    if not counts:
        await interaction.response.send_message("No recent messages tracked.", ephemeral=True)
        return
    sorted_users = sorted(counts.items(), key=lambda x: -x[1])[:limit]
    lines = []
    for uid, cnt in sorted_users:
        member = interaction.guild.get_member(uid)
        name = member.display_name if member else str(uid)
        lines.append(f"{name} — {cnt} msgs")
    await interaction.response.send_message("**Top spammers:**\n" + "\n".join(lines), ephemeral=True)

@bot.tree.command(name="suspected_users", description="List users with avg risk >= threshold.")
@app_commands.describe(threshold="Minimum average risk to show (optional)")
async def suspected_users(interaction: discord.Interaction, threshold: int = None):
    if not interaction.user.guild_permissions.manage_messages:
        await interaction.response.send_message("You need Manage Messages permission.", ephemeral=True)
        return
    gid = interaction.guild_id
    thr = threshold if threshold is not None else alert_threshold.get(gid, DEFAULT_ALERT_THRESHOLD)
    agg = {}
    counts = {}
    for m in recent_messages.get(gid, []):
        s, _ = score_message_and_get_reasons(m["content"])
        agg[m["user_id"]] = agg.get(m["user_id"], 0) + s
        counts[m["user_id"]] = counts.get(m["user_id"], 0) + 1
    avg = {}
    for uid, total in agg.items():
        avg_score = int(total / max(1, counts.get(uid, 1)))
        if avg_score >= thr:
            avg[uid] = avg_score
    if not avg:
        await interaction.response.send_message("No suspected users found.", ephemeral=True)
        return
    sorted_avg = sorted(avg.items(), key=lambda x: -x[1])[:25]
    lines = []
    for uid, sc in sorted_avg:
        member = interaction.guild.get_member(uid)
        lines.append(f"{member.display_name if member else uid} — risk {sc}/100")
    await interaction.response.send_message("**Suspected users:**\n" + "\n".join(lines), ephemeral=True)

@bot.tree.command(name="ping_user", description="Send a private mod ping to a user.")
@app_commands.describe(user="User to ping", message="Short message to send")
async def ping_user(interaction: discord.Interaction, user: discord.Member, message: str):
    if not interaction.user.guild_permissions.manage_messages:
        await interaction.response.send_message("You need Manage Messages permission.", ephemeral=True)
        return
    try:
        await user.send(f"You have a message from the moderators of **{interaction.guild.name}**:\n\n{message}")
        await interaction.response.send_message(f"✅ Ping sent to {user.mention}.", ephemeral=True)
    except Exception as e:
        await interaction.response.send_message(f"Failed to ping user: {repr(e)}", ephemeral=True)

@bot.tree.command(name="shadow_watch", description="Toggle watch status for a user.")
@app_commands.describe(user="User to add/remove from watchlist")
async def shadow_watch(interaction: discord.Interaction, user: discord.Member):
    if not interaction.user.guild_permissions.manage_messages:
        await interaction.response.send_message("You need Manage Messages permission.", ephemeral=True)
        return
    gid = interaction.guild_id
    if user.id in watchlist.get(gid, set()):
        watchlist[gid].remove(user.id)
        await _save_config_async()
        await interaction.response.send_message(f"Removed {user.mention} from watchlist.", ephemeral=True)
    else:
        watchlist[gid].add(user.id)
        await _save_config_async()
        await interaction.response.send_message(f"Added {user.mention} to watchlist.", ephemeral=True)

# -------------------------
# Run
# -------------------------
if __name__ == "__main__":
    if BOT_TOKEN == "<PASTE_YOUR_TOKEN_HERE>" or not BOT_TOKEN:
        print("ERROR: No BOT_TOKEN found. Set BOT_TOKEN environment variable or paste it in the script (not recommended).")
    else:
        bot.run(BOT_TOKEN)