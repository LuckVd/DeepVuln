# Current Goal

## Status

Completed on 2026-03-17.

## Goal

Stabilize CodeQL execution by standardizing its runtime environment and reducing environment-dependent failures in containerized scans.

## Why

CodeQL currently degrades too often on projects that require external build tools such as Maven, Gradle, `dotnet`, C/C++ toolchains, or language package managers. The project already has structured failure reporting, but the default runtime still lacks a guaranteed, reproducible toolchain baseline.

## Scope

- Provide a container image with the core CodeQL execution prerequisites preinstalled.
- Ensure Docker Compose mounts align with the runtime paths used by the application.
- Document the supported toolchains and the expected way to run CodeQL-heavy scans.
- Keep the main scan workflow stable when CodeQL prerequisites are unavailable.

## Deliverables

- Hardened [Dockerfile](/opt/projects/DeepVuln/Dockerfile) for CodeQL-oriented scans.
- Updated [docker-compose.yml](/opt/projects/DeepVuln/docker-compose.yml) with correct cache mounts and build args.
- Updated [docs/docker.md](/opt/projects/DeepVuln/docs/docker.md) describing the containerized CodeQL environment.

## Success Criteria

- The default container image includes CodeQL plus the common build environments required by DeepVuln-supported languages.
- CodeQL cache persists across Compose runs at the path the engine actually uses.
- Docker documentation clearly states what is preinstalled and what remains project-specific.

## Completion Notes

- The container image now includes CodeQL, Java/JDK, Maven, Gradle, Go, Node/npm, Ruby, .NET SDK, and native build toolchains.
- Go and CodeQL downloads now prefer official sources, then fall back to alternate mirrors when the primary source is too slow or unavailable.
- The built image was verified with toolchain checks for CodeQL, Java, Maven, Gradle, Go, .NET, and the DeepVuln CLI.

## Out Of Scope

- Refactoring CodeQL scan orchestration logic in Python.
- Adding per-language preflight checks in the engine layer.
- Supporting Swift/macOS-specific build chains inside the Linux image.
