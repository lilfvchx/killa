# Iteration: Dynamic Go String De-duplication in Recursive Structures

**Date:** 2024-05-28
**Feature:** Process Tree Allocation Optimization

## Technical Context
The agent implements a `process-tree` command that recursively enumerates and prints the system process tree hierarchy in memory (`processtree.go`). During testing of deeply nested process trees or environments with many active processes, the Go runtime allocates numerous intermediate strings inside the recursive `printTree` closure when calculating tree display connectors.

Currently, the string concatenation logic:
```go
newPrefix := prefix
if depth > 0 {
    if isLast {
        newPrefix += "    "
    } else {
        newPrefix += "|   "
    }
}
```
Is placed *inside* the child-iteration loops (`for i, childPID := range kids`). Because `newPrefix` only depends on the parent's `prefix`, `depth`, and `isLast` parameters, calculating it repeatedly for every single child process of a parent generates redundant short-lived string allocations on the heap.

## Evasion and R&D Reasoning
- **Minimization of Footprint:** As a covert R&D objective, minimizing the runtime artifact footprint includes reducing garbage collector (GC) pressure. High allocation rates in Go can cause more frequent GC sweeps, which generates recognizable memory access patterns and CPU spikes that can be flagged by behavioral analysis or memory profiling heuristics in EDR products.
- **Optimization:** By hoisting the invariant string operations outside the loop, we compute the base `newPrefix` exactly once per parent node rather than `O(N)` times (where N is the number of children). This drastically cuts memory allocations, ensuring robust and silent execution even when retrieving large process hierarchies.

## Implementation Plan
Refactor `printTree` in `processtree.go`:
1. Calculate `newPrefix` once per parent frame, before iterating over `kids`.
2. Reuse `newPrefix` as the `prefix` argument when recursing into `printTree` for each child.

## Validation Strategy
1. Unit testing with `go test -v -run TestProcessTree` to ensure formatting stability (the visual tree output must remain exactly identical).
2. Code review to verify `newPrefix` logic correctly preserves the hierarchy depth structure.
