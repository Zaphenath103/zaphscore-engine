#!/usr/bin/env python3
"""
notify_ceo.py — WAR-4: D-056
Posts a ZaphLabs shift summary to the CEO Slack channel on shift complete.
Usage: python scripts/notify_ceo.py --war WAR-1 --fixed 5 --added 2 --remaining 14 --sha abc1234
"""
import argparse
import json
import os
import urllib.request
import urllib.error
from datetime import datetime, timezone


def post_to_slack(webhook_url: str, message: dict) -> bool:
    payload = json.dumps(message).encode("utf-8")
    req = urllib.request.Request(
        webhook_url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status == 200
    except urllib.error.URLError as e:
        print(f"[notify_ceo] Slack post failed: {e}")
        return False


def build_message(war: str, fixed: int, added: int, remaining: int, sha: str) -> dict:
    total_done = fixed
    total_items = fixed + remaining
    pct = round((total_done / max(total_items, 1)) * 100, 1)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    status_emoji = "✅" if remaining == 0 else ("⚡" if pct >= 80 else "🔧")
    color = "#2eb886" if remaining == 0 else ("#ff9900" if pct >= 50 else "#cc0000")

    return {
        "attachments": [
            {
                "color": color,
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": f"{status_emoji} {war} Shift Complete — ZaphLabs",
                        },
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*Fixed this shift:*\n{fixed} items"},
                            {"type": "mrkdwn", "text": f"*New items found:*\n{added} items"},
                            {"type": "mrkdwn", "text": f"*Remaining:*\n{remaining} items"},
                            {"type": "mrkdwn", "text": f"*Completion:*\n{pct}%"},
                        ],
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": (
                                f"*Commit:* `{sha[:8]}`\n"
                                f"*Time:* {ts}\n"
                                f"*Repo:* <https://github.com/Zaphenath103/zaphscore-engine|zaphscore-engine>"
                            ),
                        },
                    },
                    *([{
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "🎯 *All items complete. Factory is clean.*",
                        },
                    }] if remaining == 0 else []),
                ],
            }
        ]
    }


def main():
    parser = argparse.ArgumentParser(description="Notify CEO Slack on war room shift complete")
    parser.add_argument("--war", required=True, help="War room name e.g. WAR-1")
    parser.add_argument("--fixed", type=int, required=True, help="Items fixed this shift")
    parser.add_argument("--added", type=int, default=0, help="New items added")
    parser.add_argument("--remaining", type=int, required=True, help="Items still pending")
    parser.add_argument("--sha", default="unknown", help="Latest commit SHA")
    args = parser.parse_args()

    webhook_url = os.environ.get("ZAPHLABS_SLACK_WEBHOOK")
    if not webhook_url:
        print("[notify_ceo] ZAPHLABS_SLACK_WEBHOOK not set — skipping Slack notification")
        print(f"[notify_ceo] Shift summary: {args.war} fixed={args.fixed} added={args.added} remaining={args.remaining}")
        return

    message = build_message(args.war, args.fixed, args.added, args.remaining, args.sha)
    success = post_to_slack(webhook_url, message)

    if success:
        print(f"[notify_ceo] ✅ Slack notification sent for {args.war}")
    else:
        print(f"[notify_ceo] ❌ Slack notification failed for {args.war}")


if __name__ == "__main__":
    main()
