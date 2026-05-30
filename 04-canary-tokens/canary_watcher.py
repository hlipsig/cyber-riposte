#!/usr/bin/env python3
"""
Watch canary/tripwire files for access and fire alerts.

Requires: pip install inotify requests pyyaml
"""

import json
import logging
import yaml
from datetime import datetime, timezone
from pathlib import Path

import inotify.adapters
import inotify.constants
import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s [canary] %(message)s")
log = logging.getLogger(__name__)


def load_config(path="deploy_canaries.yaml"):
    config_path = Path(__file__).parent / path
    with open(config_path) as f:
        return yaml.safe_load(f)


def send_alert(webhook_url, canary_path, event_types):
    now = datetime.now(timezone.utc).isoformat()
    payload = {
        "text": (
            f"CANARY TRIGGERED\n"
            f"File: `{canary_path}`\n"
            f"Events: {', '.join(event_types)}\n"
            f"Time: {now}\n"
            f"Action required: investigate host for compromise"
        )
    }
    try:
        requests.post(webhook_url, json=payload, timeout=10)
        log.info("Alert sent for %s", canary_path)
    except requests.RequestException as e:
        log.error("Failed to send alert: %s", e)


def main():
    config = load_config()
    webhook = config.get("alert_webhook", "")
    canary_paths = [c["path"] for c in config.get("canaries", [])]

    notifier = inotify.adapters.Inotify()
    watch_mask = inotify.constants.IN_ACCESS | inotify.constants.IN_OPEN

    for path in canary_paths:
        if Path(path).exists():
            notifier.add_watch(path, mask=watch_mask)
            log.info("Watching: %s", path)
        else:
            log.warning("Canary file not found, skipping: %s", path)

    log.info("Canary watcher active — %d files monitored", len(canary_paths))

    for event in notifier.event_gen(yield_nones=False):
        _, type_names, watch_path, filename = event
        full_path = f"{watch_path}/{filename}" if filename else watch_path
        log.warning("TRIGGERED: %s — events: %s", full_path, type_names)

        if webhook:
            send_alert(webhook, full_path, type_names)


if __name__ == "__main__":
    main()
