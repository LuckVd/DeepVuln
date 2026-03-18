goal:
  title: "{{GOAL_TITLE}}"
  status: in_progress
  priority: "{{GOAL_PRIORITY}}"
  objective: "{{GOAL_OBJECTIVE}}"
  acceptance_criteria:
{{ACCEPTANCE_ITEMS}}
  in_scope:
{{IN_SCOPE_ITEMS}}
  out_of_scope:
{{OUT_OF_SCOPE_ITEMS}}
  impacted_modules:
{{IMPACTED_MODULES}}
  required_checks:
    - constitution
    - protection
    - scope
    - goal
  notes:
    - Initialized by /proj-init on {{INIT_DATE}}
