"""
Ground-truth label rules, applied to window KEYS only (never to features).

A rule file is versioned JSON written by a person from an authoritative,
external source: a dataset's published attack schedule or its official
labelled CSVs. It is never derived from this repository's own outputs, so a
label cannot echo what the model sees. Labels are written to their own file
and joined to window rows by key; the extractor and the scorer never read them.

Rule file (see sensor/labels/README.md):

    {
      "label_rules_version": "cicddos2019-testday-0311-v1",
      "dataset": "CIC-DDoS2019",
      "provenance": {"source": "...", "source_files": [{"name": "...", "sha256": "..."}],
                     "verified": true, "verified_by": "...", "verified_on": "YYYY-MM-DD",
                     "notes": "..."},
      "guard_seconds": 10,
      "intervals": [
        {"id": "syn-1", "family": "SYN", "start": "2018-11-03T14:28:00+00:00",
         "end": "2018-11-03T14:35:00+00:00", "victims": ["192.168.50.4"]},
        {"id": "victim-day", "kind": "exclude", "start": "...", "end": "...",
         "victims": ["192.168.50.4"]}
      ]
    }

`kind` is "attack" (the default) or "exclude". An exclude interval names
traffic the source labels as attack but that cannot be placed reliably in
windows, such as an attacker's continuous low-rate background: windows for
its addresses are "ambiguous" unless they lie in an attack core.

Decisions:
  - Times MUST carry an explicit UTC offset. The CIC CSVs use local time
    (CIC-IDS2017 even without AM/PM), so a naive timestamp is refused rather
    than guessed.
  - A window [s, s + 5 s) for destination d is:
      "attack"    d is a victim of an interval and the window lies inside the
                  interval shrunk by guard_seconds at both ends;
      "ambiguous" d is a victim and the window touches the interval or its
                  guard band without lying inside the shrunk core, or two
                  intervals of different families claim it, or the window
                  overlaps an exclude interval for d and is in no attack core.
                  Excluded from training and metrics, never silently relabelled;
      "benign"    otherwise.
    Destinations that are not listed victims are benign by rule. This is the
    time-and-address labelling the CIC datasets themselves use; it cannot
    tell a victim's own benign traffic apart from the attack during an
    interval, which the dataset report must state.
  - Unverified rules are refused unless the caller explicitly allows them
    (tooling tests). A dataset built from them is marked untrusted.
"""

import hashlib
import ipaddress
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from .schema import WINDOW_NS

ATTACK = "attack"
BENIGN = "benign"
AMBIGUOUS = "ambiguous"
UNLABELLED = "unlabelled"
LABEL_VALUES = (ATTACK, BENIGN, AMBIGUOUS, UNLABELLED)


class LabelRuleError(ValueError):
    """The rule file is malformed, unverified, or internally inconsistent."""


KIND_ATTACK = "attack"
KIND_EXCLUDE = "exclude"


@dataclass(frozen=True)
class Interval:
    id: str
    family: str
    start_ns: int
    end_ns: int
    victims: frozenset
    kind: str = KIND_ATTACK


@dataclass(frozen=True)
class LabelRules:
    version: str
    dataset: str
    provenance: Dict[str, object]
    verified: bool
    guard_ns: int
    intervals: Tuple[Interval, ...]
    sha256: str

    def label(self, window_start_ns: int, dst_ip: str) -> Tuple[str, str, str]:
        """(label, family, interval id) for one window key."""
        w_start, w_end = window_start_ns, window_start_ns + WINDOW_NS
        core: List[Interval] = []
        touched = excluded = False
        for iv in self.intervals:
            if dst_ip not in iv.victims:
                continue
            if iv.kind == KIND_EXCLUDE:
                excluded = excluded or (w_end > iv.start_ns and w_start < iv.end_ns)
                continue
            if w_end <= iv.start_ns - self.guard_ns or w_start >= iv.end_ns + self.guard_ns:
                continue
            if w_start >= iv.start_ns + self.guard_ns and w_end <= iv.end_ns - self.guard_ns:
                core.append(iv)
            else:
                touched = True
        if touched or len({iv.family for iv in core}) > 1:
            return AMBIGUOUS, "", ""
        if core:
            return ATTACK, core[0].family, core[0].id
        if excluded:
            return AMBIGUOUS, "", ""
        return BENIGN, "", ""


def _parse_time(value: object, where: str) -> int:
    if not isinstance(value, str):
        raise LabelRuleError(f"{where}: time must be an ISO-8601 string")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise LabelRuleError(f"{where}: {error}") from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise LabelRuleError(f"{where}: time {value!r} has no UTC offset")
    # Integer arithmetic only, so the boundary is exact to the nanosecond.
    whole = int(parsed.replace(microsecond=0).timestamp())
    return whole * 1_000_000_000 + parsed.microsecond * 1_000


def _victims(values: object, where: str) -> frozenset:
    if not isinstance(values, list) or not values:
        raise LabelRuleError(f"{where}: victims must be a non-empty list")
    out = set()
    for v in values:
        try:
            out.add(str(ipaddress.ip_address(v)))
        except ValueError:
            raise LabelRuleError(f"{where}: invalid victim address {v!r}") from None
    return frozenset(out)


def parse_rules(data: bytes, allow_unverified: bool = False) -> LabelRules:
    try:
        doc = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LabelRuleError(f"not valid JSON: {error}") from None
    for key in ("label_rules_version", "dataset", "provenance", "guard_seconds", "intervals"):
        if key not in doc:
            raise LabelRuleError(f"missing field: {key}")
    provenance = doc["provenance"]
    if not isinstance(provenance, dict) or not provenance.get("source"):
        raise LabelRuleError("provenance.source is required")
    verified = provenance.get("verified") is True
    if verified and not (provenance.get("verified_by") and provenance.get("verified_on")):
        raise LabelRuleError("verified rules need provenance.verified_by and verified_on")
    if not verified and not allow_unverified:
        raise LabelRuleError("label rules are not verified (provenance.verified is not true)")
    guard = doc["guard_seconds"]
    if not isinstance(guard, (int, float)) or isinstance(guard, bool) or guard < 0:
        raise LabelRuleError("guard_seconds must be a non-negative number")

    # An empty list would silently label every window benign.
    if not isinstance(doc["intervals"], list) or not doc["intervals"]:
        raise LabelRuleError("intervals must be a non-empty list")
    intervals = []
    seen_ids = set()
    for i, raw in enumerate(doc["intervals"]):
        where = f"intervals[{i}]"
        if not isinstance(raw, dict):
            raise LabelRuleError(f"{where}: must be an object")
        iv_id, family, kind = raw.get("id"), raw.get("family", ""), raw.get("kind", KIND_ATTACK)
        if kind not in (KIND_ATTACK, KIND_EXCLUDE):
            raise LabelRuleError(f"{where}: kind must be {KIND_ATTACK!r} or {KIND_EXCLUDE!r}")
        if not iv_id or (kind == KIND_ATTACK and not family):
            raise LabelRuleError(f"{where}: id and family are required")
        if iv_id in seen_ids:
            raise LabelRuleError(f"{where}: duplicate id {iv_id!r}")
        seen_ids.add(iv_id)
        start = _parse_time(raw.get("start"), f"{where}.start")
        end = _parse_time(raw.get("end"), f"{where}.end")
        if end <= start:
            raise LabelRuleError(f"{where}: end is not after start")
        intervals.append(Interval(iv_id, family, start, end, _victims(raw.get("victims"), where), kind))
    if not any(iv.kind == KIND_ATTACK for iv in intervals):
        raise LabelRuleError("rules need at least one attack interval")

    return LabelRules(
        version=str(doc["label_rules_version"]),
        dataset=str(doc["dataset"]),
        provenance=provenance,
        verified=verified,
        guard_ns=int(round(guard * 1_000_000_000)),
        intervals=tuple(sorted(intervals, key=lambda iv: (iv.start_ns, iv.id))),
        sha256=hashlib.sha256(data).hexdigest(),
    )


def load_rules(path: str, allow_unverified: bool = False) -> LabelRules:
    with open(path, "rb") as stream:
        return parse_rules(stream.read(), allow_unverified)


def describe(rules: Optional[LabelRules]) -> Dict[str, object]:
    """Manifest entry for the rules a dataset was labelled with."""
    if rules is None:
        return {"applied": False, "trusted": False}
    return {
        "applied": True,
        "trusted": rules.verified,
        "label_rules_version": rules.version,
        "dataset": rules.dataset,
        "sha256": rules.sha256,
        "provenance": rules.provenance,
        "guard_seconds": rules.guard_ns / 1e9,
        "intervals": len(rules.intervals),
        "exclude_intervals": sum(1 for iv in rules.intervals if iv.kind == KIND_EXCLUDE),
        "families": sorted({iv.family for iv in rules.intervals if iv.kind == KIND_ATTACK}),
    }
