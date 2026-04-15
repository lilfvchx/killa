1. **Update indirect syscall resolver:** Add `NtCreateSection`, `NtMapViewOfSection`, and `NtUnmapViewOfSection` to `keyFunctions` in `indirect_syscalls_windows.go`.
2. **Implement indirect syscall wrappers:** Add `IndirectNtCreateSection`, `IndirectNtMapViewOfSection`, and `IndirectNtUnmapViewOfSection` obeying memory safety rules (conversion in `SyscallN`).
3. **Implement section injection logic:** Create `section_injection_windows.go` in `agent_code/pkg/commands/` leveraging the section mapping primitives for EDR evasion.
4. **Register the new command:** Add `RegisterCommand(&SectionInjectionCommand{})` to `registry_windows.go`.
5. **Add Mythic C2 command definition:** Create `section_injection.go` in `agentfunctions/` to make the command available in the Mythic UI.
6. **Documentation:** Create the `.ai/iteration_20240415_section_mapping.md` R&D report documenting the Windows Internals rationale.
7. **Pre-commit Steps:** Ensure proper testing, verification, review, and reflection are done by calling the pre_commit_instructions tool and following its checks.
8. **Submit PR:** Commit the branch with appropriate tags and titles, ensuring everything builds successfully.
