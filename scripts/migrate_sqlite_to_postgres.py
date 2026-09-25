#!/usr/bin/env python3
"""
Tracegate SQLite to PostgreSQL Migration Utility
Migrates all persistent production data from local SQLite (e.g. data/tracegate.db)
to a PostgreSQL instance safely, non-destructively, and with conflict protection.

Usage:
    python scripts/migrate_sqlite_to_postgres.py [--sqlite-path PATH] [--postgres-url URL] [--dry-run] [--no-backup]
"""

import sys
import os
import shutil
import sqlite3
import argparse
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Any, Optional

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("tracegate-migrator")

# Topological migration order to respect referential integrity
TABLE_TOPOLOGY: List[Tuple[str, str]] = [
    ("users", "id"),
    ("sessions", "token"),
    ("password_resets", "id"),
    ("two_factor_pending_enrollments", "id"),
    ("two_factor_recovery_codes", "id"),
    ("two_factor_pending_logins", "id"),
    ("user_github_configs", "user_id"),
    ("projects", "id"),
    ("screenshots", "id"),
    ("checklists", "id"),
    ("checklist_items", "id"),
    ("findings", "id"),
    ("evidence", "id"),
    ("reports", "id"),
    ("vapt_certificates", "certificate_id"),
    ("ai_fixes", "id"),
    ("source_discovery_results", "id"),
    ("certificate_jobs", "job_id"),
]


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Migrate Tracegate SQLite database to PostgreSQL safely and idempotently."
    )
    parser.add_argument(
        "--sqlite-path",
        default=os.getenv("SQLITE_PATH", str(PROJECT_ROOT / "data" / "tracegate.db")),
        help="Path to source SQLite database file (default: data/tracegate.db)"
    )
    parser.add_argument(
        "--postgres-url",
        default=os.getenv("DATABASE_URL") or os.getenv("POSTGRES_URL"),
        help="Destination PostgreSQL connection URL (default: DATABASE_URL / POSTGRES_URL env var)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Perform a dry run without modifying the PostgreSQL database."
    )
    parser.add_argument(
        "--no-backup",
        action="store_true",
        help="Skip creating a timestamped backup copy of the SQLite file before migration."
    )
    return parser.parse_args()


def create_sqlite_backup(sqlite_path: Path) -> Optional[Path]:
    if not sqlite_path.exists():
        logger.warning(f"SQLite file does not exist at {sqlite_path}; skipping backup.")
        return None
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = sqlite_path.with_name(f"{sqlite_path.name}.backup_{timestamp}")
    try:
        shutil.copy2(sqlite_path, backup_path)
        logger.info(f"Created SQLite backup: {backup_path}")
        return backup_path
    except Exception as e:
        logger.error(f"Failed to create backup of SQLite database: {e}")
        raise


def get_sqlite_tables(sqlite_conn: sqlite3.Connection) -> List[str]:
    cursor = sqlite_conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
    return [row[0] for row in cursor.fetchall()]


def get_postgres_columns(pg_conn: Any, table_name: str) -> List[str]:
    with pg_conn.cursor() as cur:
        cur.execute(
            """
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = %s
            ORDER BY ordinal_position
            """,
            (table_name,)
        )
        return [r[0] for r in cur.fetchall()]


def get_postgres_count(pg_conn: Any, table_name: str) -> int:
    with pg_conn.cursor() as cur:
        try:
            cur.execute(f"SELECT COUNT(*) FROM {table_name}")
            row = cur.fetchone()
            return row[0] if row else 0
        except Exception:
            pg_conn.rollback()
            return -1


def run_migration(
    sqlite_path_str: str,
    postgres_url: str,
    dry_run: bool = False,
    no_backup: bool = False
) -> int:
    sqlite_path = Path(sqlite_path_str).resolve()
    if not sqlite_path.exists():
        logger.error(f"Source SQLite database not found at {sqlite_path}")
        return 1

    if not postgres_url:
        logger.error(
            "Destination PostgreSQL URL is required. "
            "Pass --postgres-url or set DATABASE_URL / POSTGRES_URL environment variable."
        )
        return 1

    logger.info("================================================================================")
    logger.info("Tracegate Production Database Migration: SQLite -> PostgreSQL")
    logger.info("================================================================================")
    logger.info(f"Source SQLite DB:   {sqlite_path}")
    logger.info(f"Destination PG:     {postgres_url.split('@')[-1] if '@' in postgres_url else postgres_url}")
    logger.info(f"Dry Run Mode:       {dry_run}")
    logger.info("================================================================================")

    # 1. Create backup if requested
    if not no_backup and not dry_run:
        create_sqlite_backup(sqlite_path)

    # 2. Connect to SQLite
    sqlite_conn = sqlite3.connect(str(sqlite_path))
    sqlite_conn.row_factory = sqlite3.Row
    sqlite_cur = sqlite_conn.cursor()

    existing_sqlite_tables = set(get_sqlite_tables(sqlite_conn))
    logger.info(f"Detected {len(existing_sqlite_tables)} tables in SQLite database.")

    # 3. Connect to PostgreSQL
    try:
        import psycopg2
    except ImportError:
        logger.error("psycopg2 is not installed. Install psycopg2-binary to continue.")
        sqlite_conn.close()
        return 1

    connect_url = postgres_url
    if "sslmode=" not in connect_url.lower() and "localhost" not in connect_url.lower() and "127.0.0.1" not in connect_url.lower():
        sep = "&" if "?" in connect_url else "?"
        connect_url = f"{connect_url}{sep}sslmode=require"

    try:
        pg_conn = psycopg2.connect(connect_url)
        pg_conn.autocommit = False
    except Exception as e:
        logger.error(f"Failed to connect to PostgreSQL: {e}")
        sqlite_conn.close()
        return 1

    # 4. Initialize PostgreSQL schema using Tracegate database.init_db()
    try:
        from backend.database import init_db
        # Set environment variable temporarily to ensure init_db targets Postgres
        os.environ["DATABASE_URL"] = connect_url
        logger.info("Ensuring PostgreSQL schema and required columns are initialized...")
        init_db()
    except Exception as e:
        logger.warning(f"Could not run backend init_db directly: {e}. Assuming schema is already initialized.")

    # 5. Determine table sequence
    ordered_tables: List[Tuple[str, str]] = []
    seen = set()
    for tbl, pk in TABLE_TOPOLOGY:
        if tbl in existing_sqlite_tables:
            ordered_tables.append((tbl, pk))
            seen.add(tbl)

    for tbl in sorted(existing_sqlite_tables):
        if tbl not in seen:
            ordered_tables.append((tbl, "id"))

    # 6. Execute Migration Table by Table
    results: List[Dict[str, Any]] = []
    total_migrated = 0

    for tbl, pk in ordered_tables:
        sqlite_cur.execute(f"SELECT COUNT(*) FROM {tbl}")
        source_count = sqlite_cur.fetchone()[0]

        pg_cols = set(get_postgres_columns(pg_conn, tbl))
        if not pg_cols:
            logger.warning(f"Table '{tbl}' does not exist in target PostgreSQL database. Skipping.")
            results.append({
                "table": tbl,
                "sqlite_count": source_count,
                "pg_before": -1,
                "pg_after": -1,
                "migrated": 0,
                "status": "SKIPPED (No PG table)"
            })
            continue

        pg_before = get_postgres_count(pg_conn, tbl)

        if dry_run:
            results.append({
                "table": tbl,
                "sqlite_count": source_count,
                "pg_before": pg_before,
                "pg_after": pg_before,
                "migrated": 0,
                "status": f"DRY RUN (Would migrate up to {source_count})"
            })
            continue

        if source_count == 0:
            results.append({
                "table": tbl,
                "sqlite_count": 0,
                "pg_before": pg_before,
                "pg_after": pg_before,
                "migrated": 0,
                "status": "NO DATA"
            })
            continue

        # Fetch all rows from SQLite
        sqlite_cur.execute(f"SELECT * FROM {tbl}")
        rows = sqlite_cur.fetchall()

        table_migrated = 0
        table_errors = 0

        for row in rows:
            # Match columns that exist in BOTH SQLite and PostgreSQL
            valid_cols = [col for col in row.keys() if col in pg_cols]
            if not valid_cols:
                continue

            # Ensure primary key is present if we are doing ON CONFLICT
            conflict_clause = f"ON CONFLICT ({pk}) DO NOTHING" if pk in valid_cols else ""
            cols_clause = ", ".join(valid_cols)
            vals_clause = ", ".join(["%s"] * len(valid_cols))
            sql = f"INSERT INTO {tbl} ({cols_clause}) VALUES ({vals_clause}) {conflict_clause}"

            vals = [row[c] for c in valid_cols]

            with pg_conn.cursor() as cur:
                try:
                    cur.execute(sql, vals)
                    table_migrated += 1
                except Exception as row_err:
                    table_errors += 1
                    pg_conn.rollback()
                    logger.debug(f"Row insert skipped/failed in {tbl}: {row_err}")
                else:
                    pg_conn.commit()

        pg_after = get_postgres_count(pg_conn, tbl)
        total_migrated += table_migrated

        status = "SUCCESS" if table_errors == 0 else f"PARTIAL ({table_errors} errors)"
        results.append({
            "table": tbl,
            "sqlite_count": source_count,
            "pg_before": pg_before,
            "pg_after": pg_after,
            "migrated": table_migrated,
            "status": status
        })

    # 7. Print Migration Report
    logger.info("\n" + "=" * 95)
    logger.info(f"{'Table Name':<32} | {'SQLite':<8} | {'PG (Before)':<11} | {'PG (After)':<10} | {'Migrated':<8} | {'Status'}")
    logger.info("-" * 95)
    for r in results:
        logger.info(
            f"{r['table']:<32} | {r['sqlite_count']:<8} | {r['pg_before']:<11} | "
            f"{r['pg_after']:<10} | {r['migrated']:<8} | {r['status']}"
        )
    logger.info("=" * 95)
    logger.info(f"Total Rows Migrated to PostgreSQL: {total_migrated}")

    # 8. Sanity check key tables
    if not dry_run:
        with pg_conn.cursor() as cur:
            for sample_tbl in ["users", "projects", "findings", "reports", "vapt_certificates"]:
                if sample_tbl in existing_sqlite_tables:
                    try:
                        cur.execute(f"SELECT COUNT(*) FROM {sample_tbl}")
                        cnt = cur.fetchone()[0]
                        logger.info(f"Sanity Check: Table '{sample_tbl}' has {cnt} rows in PostgreSQL.")
                    except Exception as e:
                        pg_conn.rollback()
                        logger.warning(f"Could not verify sample table {sample_tbl}: {e}")

    sqlite_conn.close()
    pg_conn.close()
    logger.info("Migration completed successfully.")
    return 0


if __name__ == "__main__":
    args = parse_arguments()
    exit_code = run_migration(
        sqlite_path_str=args.sqlite_path,
        postgres_url=args.postgres_url,
        dry_run=args.dry_run,
        no_backup=args.no_backup
    )
    sys.exit(exit_code)
