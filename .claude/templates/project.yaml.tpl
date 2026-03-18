project:
  name: "{{PROJECT_NAME}}"
  type: "{{PROJECT_TYPE}}"
  description: "{{PROJECT_DESCRIPTION}}"
  primary_language: "{{PRIMARY_LANGUAGE}}"
  stack:
{{STACK_ITEMS}}

modules:
  governance-core:
    path:
      - .claude/**
      - tools/**
    status: active
    level: core
  planning-state:
    path:
      - docs/goals/**
      - docs/roadmap/**
      - docs/history/**
    status: active
    level: stable
  context-docs:
    path:
      - docs/context/**
      - docs/api/**
      - README.md
    status: active
    level: active
  product-code:
    path:
      - src/**
    status: "{{PRODUCT_CODE_STATUS}}"
    level: active

fact_sources:
  highest:
    - .claude/project.yaml
    - docs/goals/CURRENT_GOAL.yaml
    - docs/goals/INBOX.yaml
  medium:
    - docs/roadmap/ROADMAP.md
    - docs/context/FACT_SOURCES.md
    - docs/api/API.md
  derived:
    - docs/reports/review-latest.md
    - docs/history/COMMIT_HISTORY.md

required_cleanup:
  - remove_or_mark_replaced_plans
  - update_current_goal_when_scope_changes
  - keep_inbox_only_for_open_items
  - flag_dead_code_or_dead_docs_in_review
