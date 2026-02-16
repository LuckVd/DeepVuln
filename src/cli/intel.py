"""Threat intelligence CLI commands for DeepVuln."""

import asyncio

import click

from src.cli.display import (
    console,
    create_progress,
    show_banner,
    show_error,
    show_info,
    show_success,
)
from src.cli.intel_display import (
    show_cve_detail,
    show_cve_table,
    show_kev_alerts,
    show_stats,
    show_sync_result,
)
from src.layers.l1_intelligence.threat_intel import IntelService


def run_async(coro):
    """Run async coroutine synchronously."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@click.group()
def intel() -> None:
    """Threat intelligence commands for CVE/KEV/PoC management.

    Examples:
        deepvuln intel sync --days 7
        deepvuln intel search "apache struts"
        deepvuln intel show CVE-2024-21762
    """
    pass


@intel.command()
@click.option("--days", "-d", default=7, help="Number of days to sync (default: 7)")
@click.option("--full", "-f", is_flag=True, help="Perform full sync (slower)")
def sync(days: int, full: bool) -> None:
    """Sync CVE data from NVD and KEV sources.

    Examples:
        deepvuln intel sync --days 7
        deepvuln intel sync --full
    """
    show_banner()

    async def _sync():
        async with IntelService() as service:
            with create_progress() as progress:
                task = progress.add_task("[cyan]Syncing threat intelligence...", total=None)

                try:
                    if full:
                        result = await service.sync_all(days=30)
                    else:
                        result = await service.sync_cves(days=days)
                        # Also sync KEV
                        kev_count = await service.sync_kev()
                        result["kev_count"] = kev_count

                    progress.update(task, completed=True, description="[green]Sync complete!")

                    show_sync_result(result)
                    show_success("Sync Complete", f"Synced {result.get('cves_synced', 0)} CVEs")

                except Exception as e:
                    progress.update(task, completed=True, description="[red]Sync failed!")
                    show_error("Sync Failed", str(e))

    run_async(_sync())


@intel.command()
@click.option("--force", "-f", is_flag=True, help="Force re-sync even if cached")
def sync_kev(force: bool) -> None:
    """Sync Known Exploited Vulnerabilities (KEV) from CISA.

    Examples:
        deepvuln intel sync-kev
        deepvuln intel sync-kev --force
    """
    show_banner()

    async def _sync_kev():
        async with IntelService() as service:
            with create_progress() as progress:
                task = progress.add_task("[cyan]Syncing KEV catalog...", total=None)

                try:
                    count = await service.sync_kev()

                    progress.update(task, completed=True, description="[green]KEV sync complete!")
                    show_success("KEV Sync Complete", f"Synced {count} Known Exploited Vulnerabilities")

                except Exception as e:
                    progress.update(task, completed=True, description="[red]KEV sync failed!")
                    show_error("Sync Failed", str(e))

    run_async(_sync_kev())


@intel.command()
@click.argument("query")
@click.option("--limit", "-l", default=20, help="Maximum results (default: 20)")
@click.option("--kev-only", "-k", is_flag=True, help="Search only KEV CVEs")
def search(query: str, limit: int, kev_only: bool) -> None:
    """Search CVEs by keyword.

    Examples:
        deepvuln intel search "apache struts"
        deepvuln intel search "rce" --kev-only
        deepvuln intel search "sql injection" --limit 50
    """
    show_banner()

    async def _search():
        async with IntelService() as service:
            try:
                if kev_only:
                    cves = await service.get_kev_cves(limit=limit)
                    # Filter by query in description
                    query_lower = query.lower()
                    cves = [c for c in cves if query_lower in c.description.lower()][:limit]
                else:
                    cves = await service.search_cves(query, limit=limit)

                if cves:
                    show_cve_table(cves, title=f"Search Results: '{query}'")
                    console.print(f"\n[dim]Found {len(cves)} CVE(s)[/]")
                else:
                    show_info("No Results", f"No CVEs found matching '{query}'")

            except Exception as e:
                show_error("Search Failed", str(e))

    run_async(_search())


@intel.command()
@click.argument("cve_id")
def show(cve_id: str) -> None:
    """Show detailed CVE information.

    Examples:
        deepvuln intel show CVE-2024-21762
        deepvuln intel show CVE-2023-44487
    """
    show_banner()

    # Normalize CVE ID
    cve_id = cve_id.upper()
    if not cve_id.startswith("CVE-"):
        cve_id = f"CVE-{cve_id}"

    async def _show():
        async with IntelService() as service:
            try:
                cve = await service.get_cve(cve_id)

                if cve:
                    # Get related PoCs
                    pocs = await service.get_pocs_for_cve(cve_id)
                    show_cve_detail(cve, pocs)
                else:
                    show_info(
                        "CVE Not Found",
                        f"'{cve_id}' was not found in the local database.\n\n"
                        "Try syncing first:\n"
                        "  [cyan]deepvuln intel sync --days 30[/]",
                    )

            except Exception as e:
                show_error("Lookup Failed", str(e))

    run_async(_show())


@intel.command()
@click.argument("cve_id")
@click.option("--verified-only", "-v", is_flag=True, help="Show only verified PoCs")
def poc(cve_id: str, verified_only: bool) -> None:
    """Show PoCs/Exploits for a CVE.

    Examples:
        deepvuln intel poc CVE-2024-21762
        deepvuln intel poc CVE-2023-44487 --verified-only
    """
    show_banner()

    # Normalize CVE ID
    cve_id = cve_id.upper()
    if not cve_id.startswith("CVE-"):
        cve_id = f"CVE-{cve_id}"

    async def _poc():
        async with IntelService() as service:
            try:
                pocs = await service.get_pocs_for_cve(cve_id)

                if verified_only:
                    pocs = [p for p in pocs if p.verified]

                if pocs:
                    from src.cli.intel_display import show_poc_table

                    show_poc_table(pocs, title=f"PoCs for {cve_id}")
                    console.print(f"\n[dim]Found {len(pocs)} PoC(s)[/]")
                else:
                    show_info(
                        "No PoCs Found",
                        f"No PoCs found for '{cve_id}'.\n\n"
                        "PoCs may be available on:\n"
                        "  - GitHub (search manually)\n"
                        "  - ExploitDB\n"
                        "  - VulnCheck",
                    )

            except Exception as e:
                show_error("Lookup Failed", str(e))

    run_async(_poc())


@intel.command()
def stats() -> None:
    """Show threat intelligence database statistics.

    Examples:
        deepvuln intel stats
    """
    show_banner()

    async def _stats():
        async with IntelService() as service:
            try:
                stats_data = await service.get_stats()
                show_stats(stats_data)

            except Exception as e:
                show_error("Stats Failed", str(e))

    run_async(_stats())


@intel.command()
@click.option("--limit", "-l", default=20, help="Maximum results (default: 20)")
@click.option("--recent", "-r", is_flag=True, help="Show recently added KEVs")
def kev(limit: int, recent: bool) -> None:
    """Show Known Exploited Vulnerabilities.

    Examples:
        deepvuln intel kev
        deepvuln intel kev --recent --limit 10
    """
    show_banner()

    async def _kev():
        async with IntelService() as service:
            try:
                if recent:
                    kevs = await service.get_recent_kevs(days=30, limit=limit)
                else:
                    kevs = await service.get_kev_cves(limit=limit)

                if kevs:
                    show_kev_alerts(kevs, title="Known Exploited Vulnerabilities")
                    console.print(f"\n[dim]Showing {len(kevs)} of total KEV entries[/]")
                else:
                    show_info(
                        "No KEVs Found",
                        "No Known Exploited Vulnerabilities found.\n\n"
                        "Try syncing KEV data first:\n"
                        "  [cyan]deepvuln intel sync-kev[/]",
                    )

            except Exception as e:
                show_error("KEV Lookup Failed", str(e))

    run_async(_kev())


@intel.command()
@click.argument("cve_ids", nargs=-1, required=True)
def batch(cve_ids: list[str]) -> None:
    """Look up multiple CVEs at once.

    Examples:
        deepvuln intel batch CVE-2024-21762 CVE-2024-23334
    """
    show_banner()

    # Normalize CVE IDs
    normalized = []
    for cve_id in cve_ids:
        cve_id = cve_id.upper()
        if not cve_id.startswith("CVE-"):
            cve_id = f"CVE-{cve_id}"
        normalized.append(cve_id)

    async def _batch():
        async with IntelService() as service:
            cves = []

            with create_progress() as progress:
                task = progress.add_task(f"[cyan]Looking up {len(normalized)} CVEs...", total=len(normalized))

                for cve_id in normalized:
                    try:
                        cve = await service.get_cve(cve_id)
                        if cve:
                            cves.append(cve)
                    except Exception:
                        pass
                    progress.advance(task)

            if cves:
                show_cve_table(cves, title="Batch CVE Lookup Results")
                console.print(f"\n[dim]Found {len(cves)} of {len(normalized)} CVE(s)[/]")
            else:
                show_info("No Results", "None of the specified CVEs were found in the database.")

    run_async(_batch())
