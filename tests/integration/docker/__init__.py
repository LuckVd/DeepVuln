"""
Docker integration tests for language-specific builders and runtime management.

These tests verify the end-to-end flow of:
1. Builder system identifying build systems
2. Runtime version management (detection, installation, switching)
3. CodeQL database creation and analysis
4. Full scan workflow in containerized environment

All tests are marked with @pytest.mark.docker and require Docker to be available.
"""
