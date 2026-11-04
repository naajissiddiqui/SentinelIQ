#!/usr/bin/env python3
"""
generate_ransomware_behavior.py
===============================
Generates safe, controlled filesystem and process activity strictly inside
C:\\SentinelIQ-Demo to produce realistic ransomware-like endpoint telemetry
for live ML detection, CTI correlation, and automated response validation.

Safety Guarantees:
- Operates EXCLUSIVELY inside C:\\SentinelIQ-Demo.
- Does NOT touch or modify any files outside C:\\SentinelIQ-Demo.
- Does NOT use destructive cryptography or ransomware payload.
- Does NOT alter registry, network interfaces, firewall, or OS settings.
- Only creates benign, short-lived Python subprocesses.
"""

import argparse
import os
import random
import shutil
import string
import subprocess
import sys
import time
from typing import List

TARGET_DIR = os.path.abspath(r"C:\SentinelIQ-Demo")

SUBDIRECTORIES = [
    os.path.join("Documents", "Finance"),
    os.path.join("Documents", "Contracts"),
    os.path.join("Documents", "Audit"),
    os.path.join("Documents", "HR"),
    os.path.join("Desktop", "Projects"),
    os.path.join("Desktop", "Reports"),
    os.path.join("AppData", "Local", "Packages"),
    os.path.join("Downloads", "Archives"),
    os.path.join("Data", "Databases"),
    os.path.join("Data", "Records"),
]

DOCUMENT_EXTENSIONS = [
    ".docx", ".xlsx", ".pdf", ".txt", ".csv",
    ".pptx", ".json", ".xml", ".db", ".dat", ".sql", ".log"
]

ENCRYPTED_EXTENSIONS = [
    ".locked", ".encrypted", ".crypt", ".enc", ".crypted", ".ryk", ".wncry"
]

FILE_PREFIXES = [
    "quarterly_financial_statement",
    "customer_billing_records",
    "employee_payroll_data",
    "confidential_merger_memo",
    "annual_tax_return",
    "executive_strategy_deck",
    "database_credential_store",
    "vendor_payment_schedule",
    "internal_security_audit",
    "contract_master_agreement",
    "client_portfolio_summary",
    "system_backup_catalog",
    "project_deliverables_spec",
    "compliance_certification",
]


def assert_safe_path(path: str) -> None:
    """Strict security barrier: ensures path is strictly inside C:\\SentinelIQ-Demo."""
    abs_p = os.path.abspath(path)
    if not (abs_p == TARGET_DIR or abs_p.startswith(TARGET_DIR + os.sep)):
        raise RuntimeError(f"FATAL SAFETY VIOLATION: Path '{abs_p}' is outside target directory '{TARGET_DIR}'!")


def random_hex(length: int = 8) -> str:
    """Generate random hexadecimal string."""
    return "".join(random.choices(string.hexdigits.lower()[:16], k=length))


def random_alphanumeric(length: int = 16) -> str:
    """Generate random high-entropy alphanumeric string."""
    return "".join(random.choices(string.ascii_letters + string.digits, k=length))


def setup_target_directory() -> List[str]:
    """Create C:\\SentinelIQ-Demo and all target subdirectories."""
    assert_safe_path(TARGET_DIR)
    os.makedirs(TARGET_DIR, exist_ok=True)
    created_dirs = []
    for sub in SUBDIRECTORIES:
        full_sub = os.path.join(TARGET_DIR, sub)
        assert_safe_path(full_sub)
        os.makedirs(full_sub, exist_ok=True)
        created_dirs.append(full_sub)
    return created_dirs


def cleanup_target_directory() -> None:
    """Safely and completely removes C:\\SentinelIQ-Demo."""
    assert_safe_path(TARGET_DIR)
    if os.path.exists(TARGET_DIR):
        try:
            shutil.rmtree(TARGET_DIR)
            print(f"[Cleanup] Successfully removed {TARGET_DIR}")
        except Exception as e:
            print(f"[Cleanup] Error removing {TARGET_DIR}: {e}")
    else:
        print(f"[Cleanup] Directory {TARGET_DIR} does not exist.")


def create_document_file(target_dirs: List[str], file_id: int) -> str:
    """Creates a sample document file inside one of the target subdirectories."""
    chosen_dir = random.choice(target_dirs)
    prefix = random.choice(FILE_PREFIXES)
    ext = random.choice(DOCUMENT_EXTENSIONS)
    filename = f"{prefix}_{file_id}_{random_hex(6)}{ext}"
    filepath = os.path.join(chosen_dir, filename)
    assert_safe_path(filepath)

    content = (
        f"--- CONFIDENTIAL CORPORATE ASSET ---\n"
        f"Document ID: {file_id}\n"
        f"Generated: {time.strftime('%Y-%m-%dT%H:%M:%SZ')}\n"
        f"Classification: Restricted Internal\n"
        f"Payload Record: {random_alphanumeric(32)}\n"
        f"{'DATA BLOCK ' * 20}\n"
    ) * random.randint(3, 8)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)

    return filepath


def transform_file_content(filepath: str) -> None:
    """Overwrites file with high-entropy bytes and updates timestamps."""
    assert_safe_path(filepath)
    if not os.path.exists(filepath):
        return

    size = os.path.getsize(filepath)
    new_size = max(1024, size)
    high_entropy_bytes = os.urandom(new_size)

    with open(filepath, "wb") as f:
        f.write(high_entropy_bytes)

    # Adjust modification & creation timestamps to generate timestomp events (Sysmon Event ID 2)
    fake_time = time.time() - random.randint(100, 100000)
    try:
        os.utime(filepath, (fake_time, fake_time))
    except Exception:
        pass


def rename_file_to_encrypted(filepath: str) -> str:
    """Renames file to randomized high-entropy name with suspicious extension."""
    assert_safe_path(filepath)
    if not os.path.exists(filepath):
        return filepath

    dir_name = os.path.dirname(filepath)
    base_name = os.path.splitext(os.path.basename(filepath))[0]
    suspicious_ext = random.choice(ENCRYPTED_EXTENSIONS)
    rand_entropy = random_alphanumeric(14)

    new_filename = f"{base_name}_{rand_entropy}{suspicious_ext}"
    new_filepath = os.path.join(dir_name, new_filename)
    assert_safe_path(new_filepath)

    try:
        os.rename(filepath, new_filepath)
        return new_filepath
    except Exception:
        return filepath


def spawn_benign_child_process() -> None:
    """Spawns a short-lived harmless Python child process to generate process creation telemetry."""
    try:
        subprocess.Popen(
            [sys.executable, "-c", "import sys; sys.exit(0)"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        pass


def run_behavior_generator(total_duration: float = 45.0, target_files: int = 1500) -> None:
    """Runs the sustained ransomware-like activity generator."""
    assert_safe_path(TARGET_DIR)
    target_dirs = setup_target_directory()

    active_files: List[str] = []
    created_count = 0
    modified_count = 0
    renamed_count = 0
    processes_spawned = 0

    start_time = time.monotonic()
    last_log_milestone = 0

    # Number of micro-batches (roughly 5 batches per second for smooth sustained pacing)
    batch_interval = 0.20
    total_batches = int(total_duration / batch_interval)
    if total_batches < 1:
        total_batches = 1

    # Stage thresholds in normalized progress (0.0 to 1.0)
    # Stage 1: 0 - 0.22 (0 - 10s) -> Creates + some mods
    # Stage 2: 0.22 - 0.44 (10 - 20s) -> Creates + rapid mods + renames
    # Stage 3: 0.44 - 0.67 (20 - 30s) -> Creates + rapid mods + renames
    # Stage 4: 0.67 - 0.89 (30 - 40s) -> Rapid mods + renames
    # Stage 5: 0.89 - 1.00 (40 - 45s) -> Final burst

    for batch in range(total_batches):
        batch_target_time = start_time + (batch * batch_interval)
        now = time.monotonic()
        elapsed = now - start_time
        progress = min(1.0, elapsed / total_duration)

        # 1. File Creation logic
        # Spread creation across the first 4 stages (0 to 88% of duration)
        if created_count < target_files and progress < 0.88:
            create_quota = int(target_files * (progress / 0.88))
            creates_this_batch = max(0, min(create_quota - created_count, 15))
            for _ in range(creates_this_batch):
                fp = create_document_file(target_dirs, created_count + 1)
                active_files.append(fp)
                created_count += 1

        # 2. File Modification & High-Entropy Transformation logic
        # Target ~1500 modifications spread across the full run
        target_mod_total = target_files
        mod_quota = int(target_mod_total * progress)
        mods_this_batch = max(0, min(mod_quota - modified_count, 15))
        if active_files and mods_this_batch > 0:
            sample_candidates = random.sample(active_files, min(mods_this_batch, len(active_files)))
            for fp in sample_candidates:
                transform_file_content(fp)
                modified_count += 1

        # 3. File Renaming logic (starts after 10s, targets ~1000 renames with ~750 suspicious extensions)
        if progress >= 0.22:
            target_rename_total = int(target_files * 0.67)  # ~1000 renames
            rename_progress = (progress - 0.22) / (1.0 - 0.22)
            rename_quota = int(target_rename_total * rename_progress)
            renames_this_batch = max(0, min(rename_quota - renamed_count, 12))

            unencrypted_candidates = [f for f in active_files if not any(f.endswith(ext) for ext in ENCRYPTED_EXTENSIONS)]
            if unencrypted_candidates and renames_this_batch > 0:
                sample_renames = random.sample(unencrypted_candidates, min(renames_this_batch, len(unencrypted_candidates)))
                for old_fp in sample_renames:
                    new_fp = rename_file_to_encrypted(old_fp)
                    try:
                        active_files.remove(old_fp)
                        active_files.append(new_fp)
                    except ValueError:
                        pass
                    renamed_count += 1

        # 4. Process Activity: spawn 20-40 short-lived child processes across the run
        if processes_spawned < 35 and random.random() < 0.16:
            spawn_benign_child_process()
            processes_spawned += 1

        # 5. Live progress reporting at 10s milestones
        current_second = int(elapsed)
        if current_second > 0 and current_second % 10 == 0 and current_second != last_log_milestone:
            last_log_milestone = current_second
            if renamed_count > 0:
                print(f"[Activity] Elapsed: {current_second}s | Created: {created_count} | Modified: {modified_count} | Renamed: {renamed_count}")
            else:
                print(f"[Activity] Elapsed: {current_second}s | Created: {created_count} | Modified: {modified_count}")

        # Sleep remaining time of this micro-batch to sustain precise pacing
        next_tick = batch_target_time + batch_interval
        sleep_dur = next_tick - time.monotonic()
        if sleep_dur > 0:
            time.sleep(sleep_dur)

    total_elapsed = int(time.monotonic() - start_time)
    print(f"[Activity] Completed in ~{total_elapsed}s (Created: {created_count} | Modified: {modified_count} | Renamed: {renamed_count})")


def main():
    parser = argparse.ArgumentParser(
        description="SentinelIQ Safe Ransomware Behavior Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python generate_ransomware_behavior.py
  python generate_ransomware_behavior.py --duration 45 --files 1500
  python generate_ransomware_behavior.py --cleanup
        """
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=45.0,
        help="Duration of activity in seconds (default: 45)",
    )
    parser.add_argument(
        "--files",
        type=int,
        default=1500,
        help="Approximate number of files to generate (default: 1500)",
    )
    parser.add_argument(
        "--cleanup",
        action="store_true",
        help="Clean up and remove C:\\SentinelIQ-Demo completely",
    )

    args = parser.parse_args()

    if args.cleanup:
        cleanup_target_directory()
    else:
        run_behavior_generator(total_duration=args.duration, target_files=args.files)


if __name__ == "__main__":
    main()
