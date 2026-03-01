#!/usr/bin/env python3
"""Verification script for DeepVuln scan components.

This script tests:
1. L1 Attack Surface Detection - how many entry points found
2. LLM Response - whether LLM returns valid results
3. CodeQL Engine - whether CodeQL works correctly
4. Agent Analysis - whether Agent can find vulnerabilities
"""

import asyncio
import json
import logging
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Configure debug logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)

logger = logging.getLogger("verify")


async def verify_l1_detection(source_path: Path) -> dict:
    """Verify L1 attack surface detection."""
    from src.layers.l1_intelligence.attack_surface import AttackSurfaceDetector
    from src.layers.l3_analysis.llm import OpenAIClient

    logger.info("=" * 60)
    logger.info("PHASE 1: L1 Attack Surface Detection")
    logger.info("=" * 60)

    result = {
        "success": False,
        "entry_points_count": 0,
        "http_endpoints": 0,
        "rpc_services": 0,
        "mq_consumers": 0,
        "cron_jobs": 0,
        "entry_points": [],
        "llm_errors": [],
        "llm_success_count": 0,
        "llm_failure_count": 0,
    }

    try:
        from src.core.config import load_config
        config = load_config()
        llm_config = config.get("llm", {})

        # Get API key from openai section
        openai_config = llm_config.get("openai", {})
        api_key = openai_config.get("api_key") or ""
        base_url = openai_config.get("base_url") or ""
        model = llm_config.get("model") or "glm-4-flash"

        if not api_key:
            logger.error("No API key configured")
            result["error"] = "No API key configured"
            return result

        llm_client = OpenAIClient(
            model=model,
            api_key=api_key,
            base_url=base_url,
            max_tokens=llm_config.get("max_tokens", 4096),
            temperature=llm_config.get("temperature", 0.1),
        )

        detector = AttackSurfaceDetector(llm_client=llm_client)

        logger.info(f"Source path: {source_path}")
        logger.info("Running LLM full detection...")

        # Use LLM full detection
        surface_report = await detector.detect_llm_full(
            source_path,
            batch_size=50,
        )

        # Count entry points
        result["http_endpoints"] = surface_report.http_endpoints
        result["rpc_services"] = surface_report.rpc_services
        result["mq_consumers"] = surface_report.mq_consumers
        result["cron_jobs"] = surface_report.cron_jobs

        total = (
            surface_report.http_endpoints +
            surface_report.rpc_services +
            surface_report.mq_consumers +
            surface_report.cron_jobs +
            surface_report.file_inputs
        )
        result["entry_points_count"] = total

        # Get entry point details
        if surface_report.entry_points:
            for ep in surface_report.entry_points[:20]:  # First 20
                result["entry_points"].append({
                    "type": ep.type.value if hasattr(ep.type, 'value') else str(ep.type),
                    "file": ep.file,
                    "handler": ep.handler,
                    "line": ep.line,
                })

        result["success"] = True
        logger.info(f"Total entry points found: {total}")
        logger.info(f"  HTTP endpoints: {surface_report.http_endpoints}")
        logger.info(f"  RPC services: {surface_report.rpc_services}")
        logger.info(f"  MQ consumers: {surface_report.mq_consumers}")
        logger.info(f"  Cron jobs: {surface_report.cron_jobs}")

    except Exception as e:
        logger.exception(f"L1 detection failed: {e}")
        result["error"] = str(e)

    return result


async def verify_codeql(source_path: Path, language: str = "go") -> dict:
    """Verify CodeQL engine."""
    from src.layers.l3_analysis.engines.codeql import CodeQLEngine

    logger.info("=" * 60)
    logger.info("PHASE 2: CodeQL Analysis")
    logger.info("=" * 60)

    result = {
        "success": False,
        "is_available": False,
        "findings_count": 0,
        "findings": [],
        "error": None,
        "build_info": {},
    }

    try:
        engine = CodeQLEngine()

        # Check availability
        result["is_available"] = engine.is_available()
        if not result["is_available"]:
            logger.error("CodeQL not available")
            result["error"] = "CodeQL CLI not installed"
            return result

        logger.info(f"CodeQL available: {engine.codeql_path}")
        logger.info(f"Source path: {source_path}")
        logger.info(f"Language: {language}")

        # Run scan
        logger.info("Running CodeQL scan...")
        scan_result = await engine.scan(
            source_path=source_path,
            language=language,
            severity_filter=None,
        )

        result["success"] = scan_result.success

        if scan_result.success:
            result["findings_count"] = len(scan_result.findings)
            for f in scan_result.findings[:10]:  # First 10
                result["findings"].append({
                    "rule": f.rule_id,
                    "message": f.message[:100] if f.message else "",
                    "severity": f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
                    "file": f.file,
                    "line": f.line,
                })
            logger.info(f"CodeQL found {len(scan_result.findings)} findings")
        else:
            result["error"] = scan_result.error_message
            logger.error(f"CodeQL failed: {scan_result.error_message}")

    except Exception as e:
        logger.exception(f"CodeQL verification failed: {e}")
        result["error"] = str(e)

    return result


async def verify_agent(source_path: Path, entry_points: list) -> dict:
    """Verify AI Agent analysis."""
    from src.layers.l3_analysis.engines.opencode_agent import OpenCodeAgent
    from src.layers.l3_analysis.llm import OpenAIClient

    logger.info("=" * 60)
    logger.info("PHASE 3: AI Agent Analysis")
    logger.info("=" * 60)

    result = {
        "success": False,
        "findings_count": 0,
        "findings": [],
        "files_analyzed": 0,
        "error": None,
        "llm_responses": [],
    }

    try:
        from src.core.config import load_config
        config = load_config()
        llm_config = config.get("llm", {})

        # Get API key from openai section
        openai_config = llm_config.get("openai", {})
        api_key = openai_config.get("api_key") or ""
        base_url = openai_config.get("base_url") or ""
        model = llm_config.get("model") or "glm-4-flash"

        if not api_key:
            logger.error("No API key configured")
            result["error"] = "No API key configured"
            return result

        llm_client = OpenAIClient(
            model=model,
            api_key=api_key,
            base_url=base_url,
            max_tokens=llm_config.get("max_tokens", 4096),
            temperature=llm_config.get("temperature", 0.1),
        )

        # Get entry point files
        target_files = []
        if entry_points:
            for ep in entry_points[:30]:  # Max 30 files
                file_path = source_path / ep.get("file", "")
                if file_path.exists():
                    target_files.append(str(file_path))

        if not target_files:
            # Fallback to some Go files
            logger.info("No entry points, using fallback files...")
            for f in list(source_path.rglob("*.go"))[:20]:
                if "handler" in str(f) or "api" in str(f):
                    target_files.append(str(f))

        if not target_files:
            logger.error("No target files found")
            result["error"] = "No target files found"
            return result

        result["files_analyzed"] = len(target_files)
        logger.info(f"Files to analyze: {len(target_files)}")

        # Determine language
        language = "go"
        if any(".ts" in f or ".tsx" in f for f in target_files):
            language = "typescript"
        elif any(".py" in f for f in target_files):
            language = "python"

        agent = OpenCodeAgent(
            llm_client=llm_client,
            language=language,
        )

        logger.info("Running Agent analysis...")
        agent_result = await agent.scan(
            source_path=source_path,
            files=target_files,
            vulnerability_focus=[
                "sql_injection",
                "xss",
                "command_injection",
                "path_traversal",
                "ssrf",
                "hardcoded_secrets",
            ],
        )

        result["success"] = True
        result["findings_count"] = len(agent_result.findings)

        for f in agent_result.findings[:10]:  # First 10
            result["findings"].append({
                "title": f.title,
                "severity": f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
                "file": f.file,
                "line": f.line,
            })

        logger.info(f"Agent found {len(agent_result.findings)} findings")

        if not agent_result.findings:
            logger.info("No vulnerabilities found - this could be:")
            logger.info("  1. The code is actually secure")
            logger.info("  2. LLM couldn't detect issues in the code")
            logger.info("  3. Entry point files don't contain vulnerable patterns")

    except Exception as e:
        logger.exception(f"Agent verification failed: {e}")
        result["error"] = str(e)

    return result


async def main():
    """Main verification entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="Verify DeepVuln scan components")
    parser.add_argument(
        "source_path",
        type=Path,
        help="Path to source code to analyze",
    )
    parser.add_argument(
        "--language",
        default="go",
        help="Primary language for CodeQL (default: go)",
    )
    parser.add_argument(
        "--skip-codeql",
        action="store_true",
        help="Skip CodeQL verification",
    )

    args = parser.parse_args()

    if not args.source_path.exists():
        logger.error(f"Source path does not exist: {args.source_path}")
        sys.exit(1)

    logger.info(f"Starting verification for: {args.source_path}")

    results = {
        "source_path": str(args.source_path),
        "l1_detection": None,
        "codeql": None,
        "agent": None,
    }

    # Phase 1: L1 Detection
    results["l1_detection"] = await verify_l1_detection(args.source_path)

    # Phase 2: CodeQL
    if not args.skip_codeql:
        results["codeql"] = await verify_codeql(args.source_path, args.language)
    else:
        logger.info("Skipping CodeQL verification")

    # Phase 3: Agent
    entry_points = results["l1_detection"].get("entry_points", [])
    results["agent"] = await verify_agent(args.source_path, entry_points)

    # Summary
    logger.info("=" * 60)
    logger.info("VERIFICATION SUMMARY")
    logger.info("=" * 60)

    l1 = results["l1_detection"]
    logger.info(f"L1 Detection: {'✓' if l1.get('success') else '✗'}")
    logger.info(f"  Entry points: {l1.get('entry_points_count', 0)}")

    codeql = results["codeql"]
    if codeql:
        logger.info(f"CodeQL: {'✓' if codeql.get('success') else '✗'}")
        logger.info(f"  Findings: {codeql.get('findings_count', 0)}")
        if codeql.get("error"):
            logger.info(f"  Error: {codeql['error'][:100]}")

    agent = results["agent"]
    logger.info(f"Agent: {'✓' if agent.get('success') else '✗'}")
    logger.info(f"  Findings: {agent.get('findings_count', 0)}")
    if agent.get("error"):
        logger.info(f"  Error: {agent['error'][:100]}")

    # Save results to file
    output_file = Path("/tmp/verify_scan_results.json")
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2, default=str)
    logger.info(f"Results saved to: {output_file}")

    return results


if __name__ == "__main__":
    asyncio.run(main())
