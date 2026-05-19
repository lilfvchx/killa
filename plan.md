1.  **Objective**: Add Section-based process injection (`NtCreateSection`, `NtMapViewOfSection`, `NtUnmapViewOfSection`) using indirect syscalls to the agent.
2.  **Implementation**:
    *   Update `indirect_syscalls_windows.go` to add `NtCreateSection`, `NtMapViewOfSection`, `NtUnmapViewOfSection` to `keyFunctions`.
    *   Implement wrappers `IndirectNtCreateSection`, `IndirectNtMapViewOfSection`, `IndirectNtUnmapViewOfSection` in `indirect_syscalls_windows.go`.
    *   Create a new command `sectioninjection.go` that implements the `section-injection` command.
    *   Add the `section-injection` command to `registry_windows.go`.
    *   Create `sectioninjection.go` in `Payload_Type/killa/killa/agentfunctions/` for Mythic C2 integration.
3.  **Documentation**:
    *   Create an `.ai/iteration_<date>_section_injection.md` file documenting the change.
4.  **Pre-commit & Submit**:
    *   Complete pre-commit steps to ensure proper testing, verification, review, and reflection are done.
    *   Submit the PR.
