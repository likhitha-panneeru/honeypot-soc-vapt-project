#!/usr/bin/env python3
import json
from collections import Counter
import matplotlib.pyplot as plt
from datetime import datetime

LOG_FILE = "cowrie.json"

events = []
with open(LOG_FILE, "r") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue

print(f"Total log entries loaded: {len(events)}")
print("=" * 60)

event_types = Counter(e.get("eventid", "unknown") for e in events)
print("\n--- Event Type Breakdown ---")
for etype, count in event_types.most_common():
    print(f"{etype:35s} : {count}")

connections = [e for e in events if e.get("eventid") == "cowrie.session.connect"]
print(f"\nTotal connection attempts: {len(connections)}")

unique_ips = set(e.get("src_ip") for e in connections if e.get("src_ip"))
print(f"Unique source IPs: {len(unique_ips)} -> {unique_ips}")

login_success = [e for e in events if e.get("eventid") == "cowrie.login.success"]
login_failed = [e for e in events if e.get("eventid") == "cowrie.login.failed"]

print(f"\nSuccessful logins: {len(login_success)}")
print(f"Failed logins: {len(login_failed)}")

usernames_tried = Counter(e.get("username", "?") for e in (login_success + login_failed))
passwords_tried = Counter(e.get("password", "?") for e in (login_success + login_failed))

print("\n--- Top Usernames Tried ---")
for user, count in usernames_tried.most_common(10):
    print(f"{user:20s} : {count}")

print("\n--- Top Passwords Tried ---")
for pw, count in passwords_tried.most_common(10):
    print(f"{pw:20s} : {count}")

print("\n--- Successful Login Details ---")
for e in login_success:
    print(f"  username={e.get('username')}  password={e.get('password')}  src_ip={e.get('src_ip')}  time={e.get('timestamp')}")

commands = [e for e in events if e.get("eventid") == "cowrie.command.input"]
print(f"\nTotal commands executed: {len(commands)}")
print("\n--- All Commands Typed ---")
for e in commands:
    print(f"  [{e.get('timestamp')}] session={e.get('session')} -> {e.get('input')}")

command_counter = Counter(e.get("input", "?") for e in commands)
print("\n--- Most Common Commands ---")
for cmd, count in command_counter.most_common(10):
    print(f"{cmd:40s} : {count}")

downloads = [e for e in events if e.get("eventid") in ("cowrie.session.file_download", "cowrie.session.file_upload")]
print(f"\nFile download/upload attempts: {len(downloads)}")
for e in downloads:
    print(f"  {e}")

sessions = set(e.get("session") for e in events if e.get("session"))
print(f"\nTotal unique sessions: {len(sessions)}")

plt.figure(figsize=(10, 6))
labels, counts = zip(*event_types.most_common(10))
plt.barh(labels, counts, color="steelblue")
plt.xlabel("Count")
plt.title("Top 10 Event Types Captured by Honeypot")
plt.gca().invert_yaxis()
plt.tight_layout()
plt.savefig("chart_event_types.png")
plt.close()
print("\nSaved chart_event_types.png")

if usernames_tried:
    plt.figure(figsize=(8, 5))
    labels, counts = zip(*usernames_tried.most_common(10))
    plt.bar(labels, counts, color="indianred")
    plt.ylabel("Attempts")
    plt.title("Top Usernames Tried Against Honeypot")
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig("chart_usernames.png")
    plt.close()
    print("Saved chart_usernames.png")

if passwords_tried:
    plt.figure(figsize=(8, 5))
    labels, counts = zip(*passwords_tried.most_common(10))
    plt.bar(labels, counts, color="darkorange")
    plt.ylabel("Attempts")
    plt.title("Top Passwords Tried Against Honeypot")
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig("chart_passwords.png")
    plt.close()
    print("Saved chart_passwords.png")

if command_counter:
    plt.figure(figsize=(10, 6))
    labels, counts = zip(*command_counter.most_common(10))
    plt.barh(labels, counts, color="seagreen")
    plt.xlabel("Times Executed")
    plt.title("Most Common Commands Run By Attacker(s)")
    plt.gca().invert_yaxis()
    plt.tight_layout()
    plt.savefig("chart_commands.png")
    plt.close()
    print("Saved chart_commands.png")

if connections:
    times = []
    for e in connections:
        ts = e.get("timestamp")
        if ts:
            try:
                times.append(datetime.fromisoformat(ts.replace("Z", "+00:00")))
            except ValueError:
                continue
    if times:
        times.sort()
        plt.figure(figsize=(10, 5))
        plt.plot(times, range(1, len(times) + 1), marker="o", color="purple")
        plt.xlabel("Time")
        plt.ylabel("Cumulative Connections")
        plt.title("Timeline of Connection Attempts to Honeypot")
        plt.xticks(rotation=30, ha="right")
        plt.tight_layout()
        plt.savefig("chart_timeline.png")
        plt.close()
        print("Saved chart_timeline.png")

print("\n" + "=" * 60)
print("Analysis complete! Check the chart_*.png files in this folder.")
