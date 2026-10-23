# AppleAVE2 CVE Research — iOS 27.0

> [!IMPORTANT]
> This repository is research-assisted by AI agents

> [!NOTE]
> ### Open Research
> Contributions are welcome

# CVE-2026-84607 (AVEVideoEncoder race → kernel privileges): the fix, located

## What this is

iOS 27.0 advisory 149034, component **AVEVideoEncoder**: *"A sandboxed app may be able to
execute arbitrary code with kernel privileges" — "a race condition was addressed with
improved state management."* This writeup: where the fix lives and what it does.

**Answer:** a new per-frame state-consistency guard in `com.apple.driver.AppleAVE2` that
compares the client's `eEncType` against the session's `sEnc.eType` and **diverts the frame**
on mismatch. The checked field is written by a lock-free chain — fix-by-validation, not fix-by-lock.

## Fix window

The fix did **not** land at GM. It landed in the **beta 2 → beta 4** step of the iOS 27.0 cycle:

| step | what changed |
|---|---|
| b8 → GM `24A435` | **BTI only** (the `+0x2168` `__text` growth = 2148 new `bti` instrs; −40 bytes functional) |
| b1 → GM | **+7463 instructions** of real code — the beta cycle did the work |
| **b2 → b4** | **the fix step**: +68 new strings = kernel-memory hardening sweep + the one new state check |
| b4 → b5 | MCTF feature work only |

## The guard (verified in GM)

```
0xfffffff008734d14  ldr w8,  [x22, #0x58]     ; client  eEncType
0xfffffff008734d18  ldr w9,  [x19, #0x270]    ; session sEnc.eType
0xfffffff008734d1c  cmp w8, w9                ; the new state-consistency guard
0xfffffff008734d20  b.ne → divert             ; mismatch NEVER reaches frame processing
```

- String `EncType mismatch with session` — **absent in beta 2, present from beta 4 on**.
- Functional, not log-only: mismatch takes a separate block; match calls the normal
  processor `sub_fffffff008733654`.
- **Race shape:** the checked field has exactly **one writer** in the kext
  (`0xfffffff008737f98`), and its writer chain (2 levels, ends at indirect dispatch) calls
  **no lock helpers** — reader and writer live in different locking domains.
- No atomics exist in the kext at all (475k instructions decoded, zero ldxr/stxr/cas/swp) —
  lock-based only, so the fix could not be an atomics change.

## Sibling CVEs (same advisory, same fix step)

The b2→b4 sweep also added **~22 integer-overflow guards** on the `AVE_CalcBufSizeOf*`
buffer-size calculator family (pixel area, DPB, LRB, HSC/MCTF output, …):

- **CVE-2026-65410** ("improved checks") → the overflow guards.
- **CVE-2026-84616** (type confusion, "improved memory handling") → not matched by this step; lives elsewhere (possibly the userspace plugin, undiffed).
- **CVE-2026-84607** → the EncType state guard (by wording + race shape).

## Honest caveats

1. **Code-level pre-fix absence is NOT established** — the beta-2 address mapping via LIS
   alignment was unsound (§7.9 of the full report). What survives: string absence, GM
   instructions, fix step, lock-free writer.
2. **Attribution is a convergent inference** — Apple publishes no per-CVE code mapping.
3. The userspace `ave.videoencoder` / `AppleVideoEncoder.bundle` was **not diffed** across
   the window (pre-fix copies live in the beta dyld shared caches).
4. Guard-adjacent: the firmware command-slot bounds check **pre-existed** (re-worded only).



> [!NOTE]
> ### Disclaimer
> All claims cite checkable artifacts; re-verify before
trusting any of them. No exploit code is included. The fix has shipped in iOS 27.0
(24A435) — this repository documents already-patched code.
> use only for educational purposes. No exploit code.
