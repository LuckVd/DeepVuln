#!/usr/bin/env python3
"""把 DSH 的 opencode-go / deepseek-v4-flash 模型配置为 DeepVuln 的 LLM 后端。

背景：DeepVuln 的 LLM 客户端只从数据库 `llm_configs` 表构建
（scan_tasks → LLMConfigService.get_agent_scan_config / adversarial_service
→ get_verification_config），没有环境变量兜底。本脚本幂等 upsert 一行
`provider=custom, model=deepseek-v4-flash, base_url=https://opencode.ai/zen/go/v1`
的配置（config_type=both，agent 扫描与可利用性/对抗验证共用）。

模型名注意：早期基线用的 `ox-alpha-free` 已在该网关下线（实测 401 "Model
ox-alpha-free is not supported"），现默认 `deepseek-v4-flash`（与 DSH
settings.yaml 的 agent-default-model 一致，实测 200 OK）。如需换模型改
TARGET_MODEL 即可，脚本是幂等 upsert。

API key 来源（按优先级）：
  1. 环境变量 OPENCODE_GO_API_KEY
  2. DSH 凭据库 /root/.dsh/.credentials.yaml 的 refs.OPENCODE_GO_API_KEY

用法：
  # 标准场景：web 栈已起（postgres）。连 DEEPVULN_DB_URL 或默认 URL。
  python3 benchmarks/eval/seed_llm_config.py

  # 本地 sqlite 快速验证：
  DEEPVULN_DB_URL="sqlite+aiosqlite:///./data/deepvuln.db" \
      python3 benchmarks/eval/seed_llm_config.py

  # 只看将要写入什么，不改库：
  python3 benchmarks/eval/seed_llm_config.py --dry-run
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

TARGET_BASE_URL = "https://opencode.ai/zen/go/v1"
TARGET_MODEL = "deepseek-v4-flash"
CONFIG_NAME = "opencode-go / deepseek-v4-flash (DSH)"
# 来自 dsh pi-ai providers/data/opencode-go.json 的模型元数据
CONTEXT_SIZE = 1_000_000
MAX_TOKENS = 131_072
CREDENTIALS_FILE = Path("/root/.dsh/.credentials.yaml")


def resolve_api_key() -> str | None:
    key = os.environ.get("OPENCODE_GO_API_KEY")
    if key:
        return key
    if CREDENTIALS_FILE.exists():
        try:
            import yaml

            data = yaml.safe_load(CREDENTIALS_FILE.read_text()) or {}
            key = (data.get("refs") or {}).get("OPENCODE_GO_API_KEY")
            return key or None
        except Exception as exc:  # noqa: BLE001
            print(f"[warn] 读取 {CREDENTIALS_FILE} 失败: {exc}")
    return None


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    api_key = resolve_api_key()
    if not api_key:
        print("[err] 未找到 OPENCODE_GO_API_KEY（env 与 ~/.dsh/.credentials.yaml 均无）")
        return 1

    from src.web.core.config import get_database_settings
    from src.web.models.database import get_session_local, init_db
    from src.web.models.llm_config import LLMConfig

    url = os.environ.get("DEEPVULN_DB_URL") or get_database_settings().url
    print(f"[db] {url.split('@')[-1] if '@' in url else url}")

    # init_db 会建引擎并 create_all（幂等）
    await init_db(url)
    session_local = get_session_local()
    from sqlalchemy import select

    async with session_local() as db:
        existing = (
            await db.execute(
                select(LLMConfig).where(LLMConfig.base_url == TARGET_BASE_URL)
            )
        ).scalars().first()
        values = dict(
            name=CONFIG_NAME,
            provider="custom",
            api_key=api_key,
            base_url=TARGET_BASE_URL,
            model=TARGET_MODEL,
            context_size=CONTEXT_SIZE,
            temperature=0,
            max_tokens=MAX_TOKENS,
            timeout=300,
            max_retries=3,
            max_concurrent_requests=10,
            is_default=True,
            config_type="both",
        )
        if args.dry_run:
            print(f"[dry-run] 将 {'更新' if existing else '新增'} 配置: "
                  f"{CONFIG_NAME} model={TARGET_MODEL} key={api_key[:6]}***")
            return 0

        if existing:
            for k, v in values.items():
                setattr(existing, k, v)
            print(f"[ok] 已更新既有配置 id={existing.id}")
        else:
            db.add(LLMConfig(**values))
            print("[ok] 新增配置")
        await db.commit()

        # 验证两条消费链路都能取到该配置
        from src.web.services.llm_config_service import LLMConfigService

        for label, getter in (
            ("agent_scan", LLMConfigService.get_agent_scan_config),
            ("verification", LLMConfigService.get_verification_config),
        ):
            cfg = await getter(db)
            if cfg is None:
                print(f"[FAIL] {label}: 取不到配置")
                return 1
            print(f"[ok] {label} -> {cfg.name} ({cfg.provider}/{cfg.model})")
    print("[done] DeepVuln 将使用 opencode-go / deepseek-v4-flash 作为 LLM 后端")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
