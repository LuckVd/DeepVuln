#!/usr/bin/env python3
"""
Full Security Scan Script for OWASP Juice Shop
Runs all engines: Semgrep, CodeQL, AI Agent, with LLM verification and adversarial debate.
"""

import asyncio
import json
import logging
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("/opt/target/reports/scan.log"),
    ]
)
logger = logging.getLogger(__name__)

# Progress reporter
class ProgressReporter:
    """Reports progress every 5 minutes."""

    def __init__(self, interval_seconds: int = 300):
        self.interval = interval_seconds
        self.last_report = time.time()
        self.phase = "Initializing"
        self.details = {}

    def update(self, phase: str, details: dict[str, Any] | None = None):
        """Update progress and report if interval elapsed."""
        self.phase = phase
        if details:
            self.details.update(details)

        current = time.time()
        if current - self.last_report >= self.interval:
            self.report()
            self.last_report = current

    def report(self):
        """Print current progress."""
        elapsed = time.time() - self.last_report
        print(f"\n{'='*60}")
        print(f"[{datetime.now().strftime('%H:%M:%S')}] PROGRESS REPORT")
        print(f"{'='*60}")
        print(f"Phase: {self.phase}")
        for key, value in self.details.items():
            print(f"  {key}: {value}")
        print(f"{'='*60}\n")


async def run_full_scan(
    source_path: Path,
    output_dir: Path,
    progress: ProgressReporter,
) -> dict[str, Any]:
    """Run full security scan with all capabilities."""

    result = {
        "source_path": str(source_path),
        "start_time": datetime.now(UTC).isoformat(),
        "engines_requested": ["semgrep", "codeql", "agent"],
        "phases": {},
        "all_findings": [],
        "verified_findings": [],
        "adversarial_results": [],
        "statistics": {},
        "success": True,
        "errors": [],
    }

    # =========================================================================
    # Phase 0: Preparation - Tech Stack & Attack Surface Detection
    # =========================================================================

    progress.update("Phase 0: Preparation", {"step": "Tech Stack Detection"})

    from src.layers.l1_intelligence.attack_surface import AttackSurfaceDetector
    from src.layers.l1_intelligence.tech_stack_detector.detector import TechStackDetector

    tech_detector = TechStackDetector()
    tech_result = tech_detector.detect(source_path)
    primary_lang = tech_result.languages[0].language.value if tech_result.languages else "Unknown"

    progress.update("Phase 0: Preparation", {
        "primary_language": primary_lang,
        "frameworks": [fw.name for fw in tech_result.frameworks],
        "step": "Attack Surface Detection",
    })

    # Attack Surface Detection with LLM
    try:
        from src.layers.l3_analysis.llm.openai_client import OpenAIClient
        from src.core.config import get_openai_config, get_llm_config

        openai_config = get_openai_config()
        llm_config = get_llm_config()
        llm_client_for_detect = OpenAIClient(
            model="glm-5",
            api_key=openai_config.get("api_key"),
            base_url=openai_config.get("base_url"),
            max_tokens=llm_config.get("max_tokens", 4096),
        )
        surface_detector = AttackSurfaceDetector(
            llm_client=llm_client_for_detect,
            enable_llm=True,
            llm_model="glm-5",
        )
        detected_frameworks = [fw.name for fw in tech_result.frameworks] if tech_result.frameworks else None
        surface_report = await surface_detector.detect_async(source_path, frameworks=detected_frameworks)
    except Exception as e:
        logger.warning(f"LLM detection failed, using static: {e}")
        surface_detector = AttackSurfaceDetector()
        detected_frameworks = [fw.name for fw in tech_result.frameworks] if tech_result.frameworks else None
        surface_report = surface_detector.detect(source_path, frameworks=detected_frameworks)

    total_endpoints = (
        surface_report.http_endpoints +
        surface_report.rpc_services +
        surface_report.mq_consumers +
        surface_report.cron_jobs +
        surface_report.file_inputs
    )

    progress.update("Phase 0: Preparation", {
        "primary_language": primary_lang,
        "entry_points": total_endpoints,
        "step": "Complete",
    })

    result["tech_stack"] = {
        "primary_language": primary_lang,
        "frameworks": [fw.name for fw in tech_result.frameworks],
    }
    result["attack_surface"] = {
        "http_endpoints": surface_report.http_endpoints,
        "rpc_services": surface_report.rpc_services,
        "total_entry_points": total_endpoints,
    }

    # =========================================================================
    # Initialize Engines
    # =========================================================================

    progress.update("Initializing Engines", {"step": "Loading LLM Client"})

    from src.layers.l3_analysis.engines.semgrep import SemgrepEngine
    from src.layers.l3_analysis.engines.codeql import CodeQLEngine
    from src.layers.l3_analysis.engines.opencode_agent import OpenCodeAgent

    # LLM Client
    llm_client = None
    try:
        from src.core.config import get_openai_config, get_llm_config
        llm_config = get_llm_config()
        openai_config = get_openai_config()
        api_key = openai_config.get("api_key")
        base_url = openai_config.get("base_url", "https://api.openai.com/v1")
        if api_key:
            llm_client = OpenAIClient(
                model="glm-5",
                api_key=api_key,
                base_url=base_url,
                max_tokens=llm_config.get("max_tokens", 4096),
                temperature=llm_config.get("temperature", 0.1),
            )
            logger.info("LLM Client initialized")
    except Exception as e:
        logger.error(f"Failed to initialize LLM client: {e}")
        result["errors"].append(f"LLM client error: {e}")

    # Semgrep Engine
    semgrep_engine = None
    try:
        semgrep_engine = SemgrepEngine()
        if semgrep_engine.is_available():
            logger.info("Semgrep engine available")
        else:
            logger.warning("Semgrep not available")
            result["errors"].append("Semgrep not available")
            semgrep_engine = None
    except Exception as e:
        logger.error(f"Semgrep init error: {e}")
        result["errors"].append(f"Semgrep init error: {e}")

    # CodeQL Engine
    codeql_engine = None
    try:
        codeql_engine = CodeQLEngine()
        if codeql_engine.is_available():
            logger.info("CodeQL engine available")
        else:
            logger.warning("CodeQL not available")
            result["errors"].append("CodeQL not available - install from https://github.com/github/codeql-cli-binaries/releases")
            codeql_engine = None
    except Exception as e:
        logger.error(f"CodeQL init error: {e}")
        result["errors"].append(f"CodeQL init error: {e}")

    # Agent Engine
    agent_engine = None
    if llm_client:
        try:
            agent_engine = OpenCodeAgent(
                llm_client=llm_client,
                language=primary_lang.lower(),
            )
            logger.info("Agent engine available")
        except Exception as e:
            logger.error(f"Agent init error: {e}")
            result["errors"].append(f"Agent init error: {e}")

    # =========================================================================
    # Phase 1/2/3: Parallel Engine Scan
    # =========================================================================

    progress.update("Phase 1/2/3: Parallel Engine Scan", {
        "engines": "Semgrep, CodeQL, Agent",
        "step": "Preparing scan tasks",
    })

    # Prepare Agent file list
    agent_target_files = None
    if agent_engine:
        lang_to_exts = {
            "javascript": ["js", "jsx"],
            "typescript": ["ts", "tsx"],
            "python": ["py"],
            "go": ["go"],
            "java": ["java"],
        }

        all_exts = set()
        for lang in tech_result.languages:
            lang_name = lang.name.lower() if hasattr(lang, 'name') else str(lang).lower().replace("language.", "")
            exts = lang_to_exts.get(lang_name, [lang_name])
            all_exts.update(exts)

        lang_lower = primary_lang.lower()
        all_exts.update(lang_to_exts.get(lang_lower, [lang_lower]))

        excluded_dirs = {"node_modules", ".next", "dist", "build", "vendor", "__pycache__", "test", "tests"}

        def is_valid_file(f: Path) -> bool:
            return (
                f.name != "__init__.py"
                and not any(part in f.parts for part in excluded_dirs)
                and f.exists()
            )

        entry_point_files = set()
        if surface_report and surface_report.entry_points:
            for ep in surface_report.entry_points:
                ep_file = source_path / ep.file
                if is_valid_file(ep_file):
                    entry_point_files.add(str(ep_file))

        all_files = []
        for ext in all_exts:
            all_files.extend(source_path.rglob(f"*.{ext}"))

        other_files = [
            str(f) for f in all_files
            if is_valid_file(f) and str(f) not in entry_point_files
        ]

        max_files = 50
        agent_target_files = list(entry_point_files)[:max_files]
        remaining_slots = max_files - len(agent_target_files)
        if remaining_slots > 0 and other_files:
            agent_target_files.extend(other_files[:remaining_slots])

        progress.update("Phase 1/2/3: Parallel Engine Scan", {
            "agent_target_files": len(agent_target_files),
        })

    # Build parallel scan tasks
    scan_tasks = []

    if semgrep_engine and semgrep_engine.is_available():
        scan_tasks.append(("semgrep", semgrep_engine.scan(
            source_path=source_path,
            severity_filter=None,
            use_auto_config=True,
        )))

    if codeql_engine and codeql_engine.is_available():
        scan_tasks.append(("codeql", codeql_engine.scan(
            source_path=source_path,
            language=primary_lang.lower(),
            severity_filter=None,
        )))

    if agent_engine and agent_target_files:
        scan_tasks.append(("agent", agent_engine.scan(
            source_path=source_path,
            files=agent_target_files,
            vulnerability_focus=[
                "sql_injection",
                "xss",
                "command_injection",
                "path_traversal",
                "ssrf",
                "hardcoded_secrets",
                "crypto_weakness",
                "auth_bypass",
            ],
        )))

    # Execute all scans in parallel
    if scan_tasks:
        logger.info(f"Running {len(scan_tasks)} engines in parallel: {[t[0] for t in scan_tasks]}")

        # Background progress reporter
        async def report_progress_during_scan():
            while True:
                await asyncio.sleep(300)  # Report every 5 minutes
                progress.report()

        progress_task = asyncio.create_task(report_progress_during_scan())

        try:
            scan_results = await asyncio.gather(
                *[t[1] for t in scan_tasks],
                return_exceptions=True,
            )
        finally:
            progress_task.cancel()

        # Process results
        for (engine_name, _), scan_result in zip(scan_tasks, scan_results):
            if isinstance(scan_result, Exception):
                logger.error(f"{engine_name.capitalize()} error: {scan_result}")
                result["errors"].append(f"{engine_name.capitalize()} error: {scan_result}")
                result["phases"][engine_name] = {"success": False, "error": str(scan_result)}
            elif scan_result.success:
                findings_count = len(scan_result.findings) if hasattr(scan_result, 'findings') else 0
                for finding in (scan_result.findings or []):
                    result["all_findings"].append({
                        "source": engine_name,
                        "finding": finding,
                    })
                logger.info(f"{engine_name.capitalize()}: {findings_count} findings")
                result["phases"][engine_name] = {
                    "success": True,
                    "findings_count": findings_count,
                }
                progress.update("Phase 1/2/3: Parallel Engine Scan", {
                    engine_name: f"{findings_count} findings",
                })
            else:
                error_msg = scan_result.error_message if hasattr(scan_result, 'error_message') else "Unknown error"
                logger.error(f"{engine_name.capitalize()} failed: {error_msg}")
                result["phases"][engine_name] = {"success": False, "error": error_msg}

    # =========================================================================
    # Phase 4: Exploitability Verification
    # =========================================================================

    if result["all_findings"] and llm_client:
        progress.update("Phase 4: Exploitability Verification", {
            "total_findings": len(result["all_findings"]),
        })

        try:
            from src.layers.l3_analysis.rounds.round_four import RoundFourExecutor
            from src.layers.l3_analysis.rounds.models import VulnerabilityCandidate, ConfidenceLevel
            from src.core.llm import get_global_concurrency_manager
            import uuid

            executor = RoundFourExecutor(
                source_path=source_path,
                llm_client=llm_client,
                enable_llm_assessment=True,
                attack_surface_report=surface_report,
            )

            total = len(result["all_findings"])
            logger.info(f"Verifying {total} findings...")

            async def verify_single_finding(item: dict) -> dict:
                finding = item["finding"]
                try:
                    concurrency_manager = get_global_concurrency_manager()
                    async with concurrency_manager:
                        candidate = VulnerabilityCandidate(
                            id=str(uuid.uuid4())[:8],
                            finding=finding,
                            confidence=ConfidenceLevel.MEDIUM,
                            discovered_in_round=1,
                        )
                        verify_result = await executor._verify_exploitability(candidate)

                    return {
                        "source": item["source"],
                        "finding": finding,
                        "exploitability": verify_result,
                    }
                except Exception as e:
                    return {
                        "source": item["source"],
                        "finding": finding,
                        "exploitability": None,
                        "error": str(e),
                    }

            verified_results = await asyncio.gather(
                *[verify_single_finding(item) for item in result["all_findings"]],
                return_exceptions=True,
            )

            processed_results = []
            for i, r in enumerate(verified_results):
                if isinstance(r, Exception):
                    processed_results.append({
                        "source": result["all_findings"][i]["source"],
                        "finding": result["all_findings"][i]["finding"],
                        "exploitability": None,
                        "error": str(r),
                    })
                else:
                    processed_results.append(r)

            result["verified_findings"] = processed_results

            # Statistics
            status_counts = {}
            for v in processed_results:
                exp = v.get("exploitability")
                if exp:
                    status = exp.status.value
                else:
                    status = "error"
                status_counts[status] = status_counts.get(status, 0) + 1

            result["statistics"]["by_exploitability"] = status_counts
            progress.update("Phase 4: Exploitability Verification", {
                "results": str(status_counts),
            })
            logger.info(f"Verification results: {status_counts}")

        except Exception as e:
            logger.error(f"Verification error: {e}")
            result["errors"].append(f"Verification error: {e}")

    # =========================================================================
    # Phase 4.5: Adversarial Verification (LLM Debate)
    # =========================================================================

    if result["verified_findings"] and llm_client:
        progress.update("Phase 4.5: Adversarial Verification (LLM Debate)", {
            "findings_to_verify": len(result["verified_findings"]),
        })

        try:
            from src.layers.l3_analysis.verification import (
                EnhancedAdversarialVerification,
                EnhancedVerificationConfig,
            )
            from src.core.llm import get_global_concurrency_manager

            adversarial_config = EnhancedVerificationConfig(
                enabled=True,
                max_rounds=5,
                parallel_analysis=True,
                enable_evolution=True,
                enable_learning=True,
                enable_rule_extraction=True,
                skip_low_severity=False,
                skip_info_findings=True,
            )

            verifier = EnhancedAdversarialVerification(
                llm_client=llm_client,
                config=adversarial_config,
            )

            # Verify medium+ severity findings
            findings_to_verify = [
                v for v in result["verified_findings"]
                if not (v["finding"].metadata or {}).get("is_suspicious", False)
                and v["finding"].severity.value in ["critical", "high", "medium"]
            ]

            if findings_to_verify:
                logger.info(f"Adversarial verifying {len(findings_to_verify)} findings...")

                async def verify_single_adversarial(item: dict) -> dict:
                    finding = item["finding"]
                    try:
                        code_context = finding.location.snippet or finding.description
                        if finding.location.file:
                            try:
                                file_path = source_path / finding.location.file
                                if file_path.exists():
                                    code_content = file_path.read_text(encoding="utf-8", errors="ignore")
                                    lines = code_content.split("\n")
                                    start_line = max(1, finding.location.line - 5)
                                    end_line = min(len(lines), (finding.location.end_line or finding.location.line) + 5)
                                    code_context = "\n".join(lines[start_line - 1:end_line])
                            except Exception:
                                pass

                        concurrency_manager = get_global_concurrency_manager()
                        async with concurrency_manager:
                            verify_result = await verifier.verify_finding(
                                finding=finding,
                                code_context=code_context,
                            )

                        return {
                            "source": item["source"],
                            "finding": finding,
                            "adversarial": verify_result,
                        }
                    except Exception as e:
                        return {
                            "source": item["source"],
                            "finding": finding,
                            "adversarial": None,
                            "error": str(e),
                        }

                adversarial_results = await asyncio.gather(
                    *[verify_single_adversarial(item) for item in findings_to_verify],
                    return_exceptions=True,
                )

                processed_results = []
                for i, r in enumerate(adversarial_results):
                    if isinstance(r, Exception):
                        processed_results.append({
                            "source": findings_to_verify[i]["source"],
                            "finding": findings_to_verify[i]["finding"],
                            "adversarial": None,
                            "error": str(r),
                        })
                    else:
                        processed_results.append(r)

                result["adversarial_results"] = processed_results

                # Statistics
                verdict_counts = {}
                for r in processed_results:
                    adv = r.get("adversarial")
                    if adv and adv.verdict:
                        verdict = adv.verdict.verdict.value
                    else:
                        verdict = "error"
                    verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1

                result["statistics"]["by_adversarial_verdict"] = verdict_counts
                progress.update("Phase 4.5: Adversarial Verification (LLM Debate)", {
                    "verdicts": str(verdict_counts),
                })
                logger.info(f"Adversarial verdicts: {verdict_counts}")

        except Exception as e:
            logger.error(f"Adversarial verification error: {e}")
            result["errors"].append(f"Adversarial verification error: {e}")

    # =========================================================================
    # Finalize
    # =========================================================================

    result["end_time"] = datetime.now(UTC).isoformat()
    result["total_findings"] = len(result["all_findings"])

    progress.update("Scan Complete", {
        "total_findings": result["total_findings"],
        "verified": len(result.get("verified_findings", [])),
        "adversarial": len(result.get("adversarial_results", [])),
    })

    return result


def serialize_finding(obj: Any) -> Any:
    """Custom serializer for Finding objects."""
    if hasattr(obj, 'model_dump'):
        return obj.model_dump()
    elif hasattr(obj, '__dict__'):
        return {k: serialize_finding(v) for k, v in obj.__dict__.items() if not k.startswith('_')}
    elif isinstance(obj, list):
        return [serialize_finding(item) for item in obj]
    elif isinstance(obj, dict):
        return {k: serialize_finding(v) for k, v in obj.items()}
    elif isinstance(obj, Path):
        return str(obj)
    return obj


async def main():
    """Main entry point."""
    source_path = Path("/opt/target/juice-shop")
    output_dir = Path("/opt/target/reports")
    output_dir.mkdir(parents=True, exist_ok=True)

    progress = ProgressReporter(interval_seconds=300)

    print("\n" + "="*60)
    print("DEEPVULN FULL SECURITY SCAN")
    print("="*60)
    print(f"Target: {source_path}")
    print(f"Output: {output_dir}")
    print(f"Engines: Semgrep, CodeQL, AI Agent")
    print(f"Verification: LLM + Adversarial Debate")
    print("="*60 + "\n")

    progress.report()

    try:
        result = await run_full_scan(source_path, output_dir, progress)

        # Save results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # JSON report
        json_path = output_dir / f"scan_report_{timestamp}.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(serialize_finding(result), f, indent=2, default=str)
        print(f"\n[OK] JSON report saved: {json_path}")

        # Summary report
        summary_path = output_dir / f"scan_summary_{timestamp}.txt"
        with open(summary_path, "w", encoding="utf-8") as f:
            f.write("DEEPVULN SECURITY SCAN SUMMARY\n")
            f.write("="*60 + "\n\n")
            f.write(f"Target: {source_path}\n")
            f.write(f"Scan Time: {result['start_time']}\n\n")

            f.write("PHASES:\n")
            for phase, info in result.get("phases", {}).items():
                status = "OK" if info.get("success") else "FAILED"
                f.write(f"  - {phase}: {status}\n")
                if info.get("findings_count"):
                    f.write(f"    Findings: {info['findings_count']}\n")

            f.write(f"\nTOTAL FINDINGS: {result.get('total_findings', 0)}\n")

            if result.get("statistics", {}).get("by_exploitability"):
                f.write("\nEXPLOITABILITY:\n")
                for status, count in result["statistics"]["by_exploitability"].items():
                    f.write(f"  - {status}: {count}\n")

            if result.get("statistics", {}).get("by_adversarial_verdict"):
                f.write("\nADVERSARIAL VERDICTS:\n")
                for verdict, count in result["statistics"]["by_adversarial_verdict"].items():
                    f.write(f"  - {verdict}: {count}\n")

            if result.get("errors"):
                f.write("\nERRORS:\n")
                for err in result["errors"]:
                    f.write(f"  - {err}\n")

        print(f"[OK] Summary report saved: {summary_path}")

        print("\n" + "="*60)
        print("SCAN COMPLETE")
        print("="*60)
        print(f"Total Findings: {result.get('total_findings', 0)}")
        print(f"Verified: {len(result.get('verified_findings', []))}")
        print(f"Adversarial Results: {len(result.get('adversarial_results', []))}")
        print("="*60 + "\n")

    except Exception as e:
        logger.exception(f"Scan failed: {e}")
        raise


if __name__ == "__main__":
    asyncio.run(main())
