I will abstract the file reading operations in `cred_harvest_unix.go` so that they can be mocked in unit tests.
This will allow us to write a new test file, `cred_harvest_unix_test.go`, which thoroughly covers the logic of parsing files like `/etc/shadow`, `/etc/passwd`, and `/etc/gshadow`.

Here is the plan:
1.  **Refactor `cred_harvest_unix.go` to use a mockable file reading function:**
    *   Introduce a package-level variable for file reading: `var osReadFile = os.ReadFile`.
    *   Replace direct calls to `os.ReadFile` with `osReadFile`.
2.  **Create `cred_harvest_unix_test.go`:**
    *   Write test functions to verify the behavior of `credShadow` and `getUserHomes`.
    *   In the tests, replace `osReadFile` with a mock function that returns controlled file contents for `/etc/shadow`, `/etc/passwd`, and `/etc/gshadow`.
    *   Add test cases for successful parsing, handling empty lines, skipping disabled accounts (e.g., `*`, `!`), reporting warnings for hashes found in `/etc/passwd`, and returning errors when files cannot be read.
    *   Write similar tests for `getUserHomes`, simulating `/etc/passwd` contents and edge cases.
    *   Restore the original `osReadFile` function after tests (e.g. using `t.Cleanup`).
3.  **Ensure tests pass.** Run `go test` on the package and verify the new tests pass successfully and increase coverage.
4.  **Perform pre-commit checks.**
5.  **Submit PR.**
