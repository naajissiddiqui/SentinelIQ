"""
windows_event_reader.py
=======================
Reads privilege-escalation-relevant events from the Windows Security and System
logs (account/group changes, service and scheduled-task creation) for the
PrivilegeEscalationDetector. Kept separate from the Sysmon pipeline so record
IDs from different channels never interfere with Sysmon de-duplication.

Security log reads require the agent to run elevated. If a channel cannot be
read it is disabled with a single warning instead of breaking the agent loop.
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

import pywintypes
import win32evtlog

from sysmon_reader import SysmonReader


CHANNEL_QUERIES = {
    # 4720 user created, 4728/4732/4756 member added to security group,
    # 4697 service installed, 4698 scheduled task created
    "Security": "*[System[(EventID=4720 or EventID=4728 or EventID=4732 or "
                "EventID=4756 or EventID=4697 or EventID=4698)]]",
    # 7045 service installed
    "System": "*[System[(EventID=7045)]]",
}


class WindowsEventLogReader:
    def __init__(self, lookback_seconds: int = 60):
        self._parser = SysmonReader()
        self._last_record: Dict[str, int] = {c: 0 for c in CHANNEL_QUERIES}
        self._disabled: Dict[str, bool] = {c: False for c in CHANNEL_QUERIES}
        # Ignore historical events from before the agent started
        self._not_before = datetime.now(timezone.utc) - timedelta(seconds=lookback_seconds)

    def read_new(self, max_events: int = 64) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        for channel, query in CHANNEL_QUERIES.items():
            if self._disabled[channel]:
                continue
            try:
                handle = win32evtlog.EvtQuery(channel, win32evtlog.EvtQueryReverseDirection, query)
                raw = win32evtlog.EvtNext(handle, min(int(max_events), 64))
            except pywintypes.error as e:
                self._disabled[channel] = True
                print(f"[EventLogReader] Cannot read '{channel}' log ({e.strerror}); "
                      f"PE rules using it are disabled. Run the agent as Administrator.")
                continue

            parsed = [p for p in (self._parser._parse_event(ev) for ev in raw) if p]
            for event in reversed(parsed):  # oldest -> newest
                if event["record_id"] <= self._last_record[channel]:
                    continue
                self._last_record[channel] = event["record_id"]
                if event["timestamp"] < self._not_before:
                    continue
                event["channel"] = channel.lower()
                results.append(event)
        return results
