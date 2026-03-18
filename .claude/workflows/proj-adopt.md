# Proj-Adopt Workflow

1. Read `CONSTITUTION.md`.
2. Validate the target repository path.
3. Copy ClaudeDevKit command and governance files into the target repository.
4. Infer language, repository type, and active module paths from the live project layout.
5. Write an adoption brief in the target repository.
6. Run `tools/proj_init.sh --mode adopt` inside the target repository.
7. Leave the target repository with a generated `project.yaml`, `CURRENT_GOAL`, `CURRENT_TASKS`, `INBOX`, and `ROADMAP`.
