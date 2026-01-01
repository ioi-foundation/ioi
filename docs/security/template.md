# <ADVISORY_ID> — <TITLE>

**Date Published:** <YYYY-MM-DD>  
**Severity:** <Critical | High | Medium | Low> (CVSS <score>)  
**CVSS Vector:** <vector string>  
**Status:** <✅ Patched | 🟠 Under Review | 🔴 Unpatched>  
**Fixed In:** Commit [`<commit>`](https://github.com/ioi-network/ioi/commit/<commit>)

---

## 1. Summary

<Concise explanation of what was discovered, where it occurs, and the general nature of the vulnerability.  
Mention affected subsystem(s) and what attack surface it exposes.>

---

## 2. Affected Components

| Layer | File(s) | Impact |
|-------|----------|--------|
| <Module/Crate> | `<path/to/file.rs>` | <Short description of impact> |
| <Module/Crate> | `<path/to/file.rs>` | <Short description of impact> |

---

## 3. Vulnerability Details

### Root Cause

<Describe the flawed logic, missing validation, or unsafe assumption. Include code snippets if helpful.>

```rust
// Vulnerable pattern example
<code snippet>
````

Explain why this logic fails and how it can be exploited.

### Exploit Scenario

1. <Step 1 of exploit>
2. <Step 2>
3. <Expected system behavior>  
4. <Observed vulnerable behavior>  

<Describe end result: escalation, denial, or corruption.>

---

## 4. Proof-of-Concept

<Minimal working example or test demonstrating exploitability.>

```rust
<PoC test code or API sequence>
```

---

## 5. Impact Assessment

| Vector        | Description                                   |
| ------------- | --------------------------------------------- |
| **Economic**  | <Financial or stake impact>                   |
| **Liveness**  | <How consensus or chain operation could halt> |
| **Integrity** | <How state could diverge or replay occur>     |

---

## 6. Remediation

### Code Fix

1. **<Fix name>**

   ```rust
   <Patched code example>
   ```

   <Explain how this removes attack vector.>

2. **Additional Safeguards**

   * <e.g., canonicalization, range checks, signature verification>
   * <e.g., added new unit or integration tests>

### Patch Reference

* Commit: [`<commit>`](https://github.com/ioi-network/ioi/commit/<commit>)
* Modules: `<affected modules>`
* Tag: `<version tag>`

---

## 7. Verification

| Verification Step | Result                          |
| ----------------- | ------------------------------- |
| Unit / E2E Tests  | ✅ Passed                        |
| Regression Check  | ✅ Exploit attempt rejected      |
| Network Liveness  | ✅ Chain remains operational     |
| Invariant Tests   | ✅ All economic constraints hold |

---

## 8. Timeline

| Date (UTC)   | Event                               |
| ------------ | ----------------------------------- |
| <YYYY-MM-DD> | Vulnerability discovered            |
| <YYYY-MM-DD> | Root cause confirmed                |
| <YYYY-MM-DD> | Patch implemented                   |
| <YYYY-MM-DD> | Patch merged and advisory published |

---

## 9. Acknowledgements

<Names or teams credited for discovery, triage, fix, or review.>

---

## 10. References

* [CWE Reference](https://cwe.mitre.org/)
* [CVSS Calculator](https://www.first.org/cvss/)
* [Related advisories or ecosystem examples]

---

*Document version:* 1.0
*Last updated:* <YYYY-MM-DD>

```
