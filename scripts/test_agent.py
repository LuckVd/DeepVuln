#!/usr/bin/env python3
"""Quick test for Agent analysis."""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


async def test_agent():
    from src.layers.l3_analysis.engines.opencode_agent import OpenCodeAgent
    from src.layers.l3_analysis.llm import OpenAIClient
    from src.core.config import load_config

    config = load_config()
    llm_config = config.get("llm", {})
    openai_config = llm_config.get("openai", {})

    api_key = openai_config.get("api_key", "")
    base_url = openai_config.get("base_url", "")
    model = llm_config.get("model", "glm-5")

    print(f"Model: {model}")
    print(f"Base URL: {base_url}")
    print(f"API Key: {api_key[:10]}..." if api_key else "No API key")

    llm_client = OpenAIClient(
        model=model,
        api_key=api_key,
        base_url=base_url,
        max_tokens=4096,
        temperature=0.1,
    )

    agent = OpenCodeAgent(llm_client=llm_client)

    # Test files
    source_path = Path("/opt/target/PandaWiki/backend")
    target_files = [
        str(source_path / "handler/v1/auth.go"),
        str(source_path / "handler/v1/file.go"),
    ]

    print(f"\nAnalyzing {len(target_files)} files...")
    for f in target_files:
        print(f"  - {f}")

    result = await agent.scan(
        source_path=source_path,
        files=target_files,
        language="go",
        vulnerability_focus=["sql_injection", "xss", "command_injection", "path_traversal"],
    )

    print(f"\n=== Agent Result ===")
    print(f"Success: {result.success}")
    print(f"Findings: {len(result.findings)}")

    for i, f in enumerate(result.findings[:5], 1):
        print(f"\n{i}. {f.title}")
        print(f"   Severity: {f.severity}")
        print(f"   File: {f.location.file}:{f.location.line}" if f.location else "   File: unknown")
        print(f"   Description: {f.description[:100]}..." if f.description else "")

    if result.error_message:
        print(f"\nError: {result.error_message}")


if __name__ == "__main__":
    asyncio.run(test_agent())
