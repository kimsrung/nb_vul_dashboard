"""
Cleanup Redundant Duplicate Audit Logs
======================================
Identifies and cleans up historical duplicate 'MISP_EVENT_TRIGGERED' records
in the audit_logs table caused by ZeroMQ multi-topic bursts and unthrottled
logging.

Usage:
    # 1. Preview duplicates without making any changes (dry run):
    docker compose exec backend python cleanup_duplicate_audit_logs.py --dry-run
    # or locally:
    PYTHONPATH=. venv/bin/python cleanup_duplicate_audit_logs.py --dry-run

    # 2. Safely remove duplicate records:
    docker compose exec backend python cleanup_duplicate_audit_logs.py --apply
    # or locally:
    PYTHONPATH=. venv/bin/python cleanup_duplicate_audit_logs.py --apply
"""

import sys
import argparse
import asyncio
from typing import List, Dict, Any
from sqlalchemy import select, delete
from app.core.database import AsyncSessionLocal
from app.models.audit_log import AuditLog


async def find_and_clean_duplicates(apply_changes: bool = False, cooldown_window_seconds: int = 3600):
    async with AsyncSessionLocal() as session:
        # Retrieve all MISP_EVENT_TRIGGERED logs ordered by target_id and timestamp
        stmt = (
            select(AuditLog)
            .where(AuditLog.action == "MISP_EVENT_TRIGGERED")
            .order_by(AuditLog.target_id, AuditLog.created_at.asc(), AuditLog.id.asc())
        )
        result = await session.execute(stmt)
        all_logs: List[AuditLog] = result.scalars().all()

        print(f"[*] Total 'MISP_EVENT_TRIGGERED' audit records scanned: {len(all_logs)}")

        duplicate_ids_to_remove: List[int] = []
        cve_duplicate_counts: Dict[str, int] = {}
        kept_records_count = 0

        # Group by target_id (cve_id)
        current_target = None
        last_kept_log = None

        for log in all_logs:
            target = log.target_id or ""
            if target != current_target:
                # New CVE encountered: keep first record
                current_target = target
                last_kept_log = log
                kept_records_count += 1
                continue

            # Compare with last kept record for this CVE
            time_diff = (log.created_at - last_kept_log.created_at).total_seconds()
            curr_details = log.details or {}
            last_details = last_kept_log.details or {}

            curr_count = curr_details.get("affected_assets_count", 0)
            last_count = last_details.get("affected_assets_count", 0)
            curr_type = curr_details.get("match_type", "")
            last_type = last_details.get("match_type", "")

            state_identical = (curr_count == last_count) and (curr_type == last_type)

            # If within cooldown and identical state, flag as redundant duplicate
            if time_diff < cooldown_window_seconds and state_identical:
                duplicate_ids_to_remove.append(log.id)
                cve_duplicate_counts[target] = cve_duplicate_counts.get(target, 0) + 1
            else:
                # State changed or cooldown passed: keep this record as new reference point
                last_kept_log = log
                kept_records_count += 1

        print(f"[*] Analysis complete:")
        print(f"    - Unique & state-change records to KEEP: {kept_records_count}")
        print(f"    - Redundant duplicate records to REMOVE: {len(duplicate_ids_to_remove)}")
        print(f"    - Distinct CVEs with duplicates: {len(cve_duplicate_counts)}")

        if cve_duplicate_counts:
            print("\n[*] Top 10 CVEs with duplicate audit rows:")
            sorted_dups = sorted(cve_duplicate_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            for cve, count in sorted_dups:
                print(f"    - {cve}: {count} redundant rows")

        if not duplicate_ids_to_remove:
            print("\n[+] Database is clean! No redundant duplicate audit records found.")
            return

        if not apply_changes:
            print("\n[!] DRY RUN ONLY. No rows were deleted. Run with --apply to purge duplicates.")
        else:
            print(f"\n[*] Deleting {len(duplicate_ids_to_remove)} redundant duplicate records...")
            # Batch delete in chunks of 500
            chunk_size = 500
            for i in range(0, len(duplicate_ids_to_remove), chunk_size):
                chunk = duplicate_ids_to_remove[i:i + chunk_size]
                del_stmt = delete(AuditLog).where(AuditLog.id.in_(chunk))
                await session.execute(del_stmt)

            await session.commit()
            print(f"[+] Successfully purged {len(duplicate_ids_to_remove)} redundant audit records from database!")


def main():
    parser = argparse.ArgumentParser(description="Purge redundant MISP_EVENT_TRIGGERED audit logs.")
    parser.add_argument("--apply", action="store_true", help="Apply deletion of redundant duplicate rows.")
    parser.add_argument("--dry-run", action="store_true", help="Preview duplicates without deleting (default).")
    parser.add_argument("--cooldown", type=int, default=3600, help="Cooldown window in seconds (default: 3600).")
    args = parser.parse_args()

    apply = args.apply and not args.dry_run
    asyncio.run(find_and_clean_duplicates(apply_changes=apply, cooldown_window_seconds=args.cooldown))


if __name__ == "__main__":
    main()
