#!/usr/bin/env python3
"""Test the new modular scan service.

This script tests the new coroutine-based scanning architecture.
"""

import asyncio
from pathlib import Path

from src.web.services.scan import ScanOrchestrator, ScanConfig, ScanType


async def test_scan():
    """Test a basic scan."""

    # Test configuration
    scan_id = 999  # Test scan ID
    project_id = 7  # Your test project ID
    source_path = Path("/opt/projects/DeepVuln")  # Scan self

    # Create scan configuration
    config = ScanConfig(
        scan_type=ScanType.BASE,
        engines=["semgrep"],  # Only use semgrep for quick test
        llm_verify=False,
        adversarial=False,
        include_low_severity=True,
    )

    # Create orchestrator
    print(f"Creating scan orchestrator for scan {scan_id}...")
    orchestrator = ScanOrchestrator(
        scan_id=scan_id,
        project_id=project_id,
        source_path=source_path,
        config=config,
    )

    # Run scan (without database for testing)
    print("Starting scan...")
    result = await orchestrator.run()

    # Print results
    print("\n" + "="*60)
    print("SCAN RESULTS")
    print("="*60)
    print(f"Success: {result.get('success')}")
    print(f"Duration: {result.get('duration_seconds', 0):.2f} seconds")

    stats = result.get('statistics', {})
    print(f"\nStatistics:")
    print(f"  Total files: {stats.get('total_files', 0)}")
    print(f"  Indexed files: {stats.get('indexed_files', 0)}")
    print(f"  Analyzed files: {stats.get('analyzed_files', 0)}")
    print(f"  Findings: {stats.get('findings_count', 0)}")

    findings = result.get('findings', [])
    print(f"\nFound {len(findings)} findings:")
    for i, finding in enumerate(findings[:5]):  # Show first 5
        print(f"  {i+1}. [{finding.get('severity', 'unknown')}] {finding.get('title', 'Untitled')}")
        print(f"     {finding.get('file_path', '')}:{finding.get('line_start', 0)}")

    if len(findings) > 5:
        print(f"  ... and {len(findings) - 5} more")

    print("\n" + "="*60)


if __name__ == "__main__":
    print("Testing DeepVuln Modular Scan Service")
    print("="*60)

    try:
        asyncio.run(test_scan())
        print("\n✅ Test completed successfully!")
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
