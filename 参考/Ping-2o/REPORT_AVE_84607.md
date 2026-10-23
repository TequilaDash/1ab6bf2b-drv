> **NOTICE — AI-GENERATED SECURITY RESEARCH.** Written 100% by autonomous AI agents
> (no human authoring or line-by-line review). Authorized security research /
> coordinated disclosure only. All claims cite checkable artifacts (offsets, commands,
> hashes); re-verify before trusting any of them.

# REPORT — CVE-2026-84607 (AVEVideoEncoder race → kernel privileges): locating the fix

**Status (FINAL, round 18):** **located.** The fix for CVE-2026-84607 is a new per-frame
state-consistency guard in `com.apple.driver.AppleAVE2` — added in the beta-2 → beta-4 hop of the
iOS 27.0 cycle, present in the shipped 24A435 build — that compares the client's `eEncType`
against the session's `sEnc.eType` and **diverts the frame** on mismatch, on a path whose writer
chain holds no client lock. Proven: the fix step, the GM `+0x2168` being BTI-only, the absence of
any added lock/unlock call in the cycle, the newness of the check's string, the guard's
instructions and divert behaviour, the lock-free writer chain, and the lock/unlock helper pair.
Two verification threads were left open when the session's analysis budget ran out and four
delegated agents produced no output across six rounds: (i) the *code-level* pre-fix absence in
beta 2 (the address-mapping route to it was unsound and is withdrawn — §7.9 documents the repair
method), and (ii) the userspace `ave.videoencoder` / `AppleVideoEncoder.bundle` diff. The CVE-to-
code mapping itself is a convergent inference: Apple publishes no per-CVE code mapping.

---

## 0. Target

Apple advisory 149034 (iOS 27 / iPadOS 27, released 2026-09-14), component
**AVEVideoEncoder**: *"A sandboxed app may be able to execute arbitrary code with kernel
privileges"* / *"A race condition was addressed with improved state management"*,
credited to Ruslan Dautov. Fixed in iOS 27.0 = build **24A435** (the build in
`/Users/pauyedin/24A435__iPhone17,5` and in
`iPhone17,5_27.0_24A435_Restore.ipsw`).

Two sibling AVEVideoEncoder CVEs are in the same advisory and are presumed to share the
same fix window: **CVE-2026-84616** (type confusion, *improved memory handling*, Peter
Malone) and **CVE-2026-65410** (*improved checks*, Calif.io + Claude/Anthropic Research).

---

## 1. What the prior session got wrong (and why it mattered)

`REPORT_27_0_CVE_HUNT.md` §6 concluded that the RC "hardened precisely these surfaces" and
listed `com.apple.driver.AppleAVE2 | +0x2168 | size-only` as an unaudited target. The
`+0x2168` is real, but it is **not** code that Apple wrote for a fix:

| measurement | beta 8 `24A5430a` (pre-GM) | GM `24A435` | delta |
|---|---|---|---|
| `__TEXT_EXEC.__text` | `0x1cdec0` | `0x1d0028` | **+0x2168** |
| `bti` instruction count | 926 | **3074** | **+2148** |
| `retab` count | 2086 | 2086 | 0 |
| `pacibsp` count | 2236 | 2236 | 0 |
| `__text` **after removing `bti`** | `0x1cd048` | `0x1cd020` | **−0x28** |

2148 `bti` × 4 bytes = 8592 ≈ the whole `+0x2168` (8552). Removing them leaves a
**−40-byte (−10 instruction)** residual. `__TEXT.__cstring` differs in exactly **4 bytes**,
and those 4 bytes are the build stamp: `Aug 13 2026` `22:19:55` → `21:32:58`. `__TEXT.__const`
and `__TEXT.__os_log` are byte-identical.

**Conclusion: between the last 27.0 beta and the 27.0 GM, `AppleAVE2` received no functional
change beyond BTI hardening and a net deletion of ~10 instructions.** CVE-2026-84607's fix is
therefore *not* in that step, and any hunt that assumed the GM-only delta was the fix was
pointed at build hardening.

The remaining 10-instruction deletion is not yet attributed (candidate: a path removal —
cf. the "addressed by removing the vulnerable code" wording Apple uses elsewhere).

---

## 2. Baseline acquisition (the enabling step)

Beta restore images for iOS 27.0 are **still Apple-signed** (verified 2026-09-15 via
betaprofile.dev), so the vulnerable binaries are obtainable without downloading 12 GB:

```bash
# list members and range-fetch just the kernelcache from the remote IPSW
python3 scripts/ds_ipsw_range.py "<IPSW URL>" --list
python3 scripts/ds_ipsw_range.py "<IPSW URL>" --get kernelcache.release.v59 --out /tmp/beta8/kc
ipsw kernel dec /tmp/beta8/kc
ipsw kernel extract -a -o /tmp/beta8/kexts /tmp/beta8/kc.decompressed
```

| build | role | URL | kext file size | `__text` |
|---|---|---|---|---|
| `24A5355q` (beta 1) | the build the campaign originally analysed (`FINDINGS.md` §98) | `.../5CA34995-.../iPhone17,5_27.0_24A5355q_Restore.ipsw` | 2,955,112 | `0x1c6a50` |
| `24A5430a` (beta 8) | last pre-GM | `.../ab87bc08-.../iPhone17,5_27.0_24A5430a_Restore.ipsw` | 3,004,288 | `0x1cdec0` |
| `24A435` (GM) | fixed | local IPSW / extraction | 3,020,688 | `0x1d0028` |

**Control that the fetched baseline is the right build:** the extracted beta-8 `__text` size
`0x1cdec0` is byte-exact the value `blacktop/ipsw-diffs` reports for
`27_0_24A5430a_vs_27_0_24A435`, and the GM value `0x1d0028` matches too.

Note the two kexts sit at **different kernelcache bases** (code +`0x45C00`, data +`0x27B90`),
so all comparison must be done on `__text`-relative offsets, never raw VAs.

---

## 3. The real fix window (measured)

With `bti` stripped from both streams and aligned on unique 32-byte windows chained by
longest-increasing-subsequence (`scripts/ds_ave_align.py`):

| comparison | functional growth (de-BTI) |
|---|---|
| beta 8 `24A5430a` → GM `24A435` | **−0x28** (BTI only) |
| beta 1 `24A5355q` → GM `24A435` | **+0x749c bytes (+7463 instructions)** |

So the AVE2 kext gained ~30 KB of genuine code **during the beta cycle**, not at GM. The
per-pair section sizes from `ipsw-diffs` agree: the kext's `__cstring` grew in
`b1→b2` (+0x525), `b3→b4` (+0xbb5) and `b4→b5` (+0x126) — i.e. real changes with new
strings, then nothing until the BTI-only GM rebuild.

**The CVE-2026-84607 fix therefore landed in one of the `b1→b2`, `b3→b4` or `b4→b5` steps**
(or a 26.x backport), and beta 1 `24A5355q` — the build the campaign analysed when it wrote
`FINDINGS.md` §98 — is a genuine pre-fix baseline.

---

## 4. Findings already visible in the site diff

`scripts/ds_ave_sitediff2.py` (BTI-aware, relocation-masked) over the state-management
anchors, beta 1 vs GM. After masking, most differences are noise of two kinds — branch
targets, and **log line numbers baked into format strings** (e.g. `mov w9, #0x906` →
`#0x986`, a uniform `+0x80` shift = the source file grew ~128 lines). Two differences are
*semantic* and worth following:

1. **The client object grew by 0x10 bytes.** At the `pClient->eKPIState !=
   AVE_Client_State_None` assert site the field displacement moved `add x0, x19, #0xc48`
   → `#0xc58` (beta 1 → GM). A field added/moved inside the AVE2 client struct is exactly
   the kind of change a state-management fix makes.
2. **A deletion at the same site:** `mov w0, #6` present in beta 1 and absent in GM.

Both are in the function containing the `eKPIState` assert — the close/detach state check
the prior campaign flagged (`FINDINGS.md` §98.1).

---

## 5. Other verified results

* **UC dispatch located in 24A435 by a unique opcode pattern**, not by stale offsets: the
  idiom `sub w8, w1, #1 ; cmp w8, #0xf` (selectors 1..16, `FINDINGS.md` §98) occurs
  **exactly once** in the kext, at **`0xfffffff008876e4c`**. The beta-era value
  `0xfffffff00887268c` is stale by `+0x47C0`. Any future claim about "the UC dispatch at
  0x887268c" is wrong for this build.
* **Zero atomics.** A full decode of all 475,146 instructions in the GM `__text` finds **no**
  `ldxr/stxr/ldaxr/stlxr/ldadd/cas/swp` — the kext is lock-based only. So the fix cannot be
  an atomics change; it must be lock scope/ordering or state-field discipline.
* **The AVE plugin is not the GM-step fix site either.** `ave.videoencoder` (and its twin
  `AppleVideoEncoder.bundle`) changed only cosmetically at GM: `__text` −0x58 with 19
  functions touched by small deltas. Caveat: the negative deltas (−4/−12/−24/−32/−164) show
  those are not pure BTI, so the plugin still needs its own pre-fix baseline — which lives in
  the dyld shared cache, not the kernelcache.
* Sanity check on the corpus: `ipsw-diffs` publishes plugin *function-level* diffs for only
  some pairs (37 entries for `b2→b3`, 19 for `b8→GM`, 0 for `b1→b2`), so "changed only at
  step X" claims from that corpus alone are not safe.

---

## 6. Round 3 — bisect of the fix window

### 6.1 Which step changed what (marker tracking across builds)

All six builds were obtained (b1/b2/b4/b5/b8/GM; each is a ~23 MB range fetch) and the
markers tracked across them:

| build | `__text` | SwC obj `add x0,x8,#` | client obj `add x0,x19,#` | clientClose log lines |
|---|---|---|---|---|
| b1 `24A5355q` | `0x1c6a50` | `0x478` | `0xc48` | …1512, 1992 |
| b2 `24A5370h` | `0x1c9b10` | `0x478` | `0xc48` | …1512, 1992 |
| b4 `24A5390f` | `0x1cd2a0` | **`0x4f8`** | `0xc50` | …1512, 1992 |
| b5 `24A5408d` | `0x1cdec0` | `0x4f8` | **`0xc58`** | **…1533, 2013** |
| b8 `24A5430a` | `0x1cdec0` | `0x4f8` | `0xc58` | …1533, 2013 |
| GM `24A435` | `0x1d0028` | `0x4f8` | `0xc58` | …1533, 2013 |

* **b2→b4**: the `AVE_SwC` object grew **0x80 bytes** before offset `0x478`
  (`add x0,x8,#0x478`→`#0x4f8`; also `0x19478`→`0x194f8`).
* **b4→b5**: the client object gained **8 more bytes** (`0xc50`→`0xc58`), the client-state
  source file grew **98 lines**, the close-path file **21 lines**, `__cstring` +0x126, and
  functional growth is **+0xc20 bytes in 28 insertion events**. The largest insertion
  (`0x568` bytes) is *inside the function containing the `eKPIState` assert*, and the added
  code is conditionals feeding a log/assert call:
  `and w10,w10,#1` / `ldrb w11,[x24,#0x153]` / `and w11,w11,#1` / `stp` … then an
  `adrp`+`add` format-string load, an `adrp`+`ldr` global, and an `adrp` for a third arg.
* b5→b8: no change. b8→GM: BTI only.

### 6.2 A hard negative: no locking was added anywhere

The two null-safe deref-then-call helpers that the prior analysis identified as the
`IOLockLock`/unlock wrappers (GM `0xfffffff0086e5594` / `0xfffffff0086e55d4`) were located in
**every** build by their exact 8-instruction signature, and their **total `bl` caller count is
311 in all six builds** (b1 311, b2 311, b4 311, b5 311, b8 311, GM 311).

⇒ **The 27.0 cycle added no lock/unlock calls.** So CVE-2026-84607's "improved state
management" is **not** an added lock. It must be one of: a reordering of an existing
lock/unlock (scope change — invisible to call counts), a new **state field** plus checks on it
(consistent with the +8 bytes at `+0xc58` and the new `[x24,#0x153]` byte reads), or an
ownership/refcount change. Caveat: an invariant *total* does not exclude a moved call site.

**Current best hypothesis (unproven):** the b4→b5 step — new 8-byte client field + state
checks in the close/`eKPIState` path — carries the CVE-2026-84607 fix; the b2→b4 `SwC` +0x80
growth is the alternative. Delegated to an agent for the decisive read
(`analysis/ave84607_beta_bisect.md`).

### 6.3 Independent confirmation from the UC-dispatch agent

A separate agent (Binary Ninja only) independently located `AppleAVE2UserClient::externalMethod`
at **`0xfffffff008876e2c`** (matching my unique-opcode-pattern hit at `0xfffffff008876e4c`,
which sits inside it), proved **selectors 1..15** (`b.hs` = unsigned reject), reconstructed the
dispatch table at `0xfffffff007f1a1b8` (16×0x28; `Prepare` takes `0x12c08` bytes, `Start`
`0x12c18`), and **corrected the chained-fixup base to `0xfffffff007004000`** (AGENTS.md's
`0xfffffff007000000` is off by 0x4000). It also confirmed all 15 handlers run inside the
`this+0x158` client lock with no early unlock, and raised one live lead — the async-result
sender `sub_fffffff0088807ec`, whose only caller is the driver completion path
(`sub_fffffff00873eedc` → `0xfffffff00873f360`), which holds no client lock while reading
`UC+0x100/0x108/0x110/+0x160`. My own alignment of that region shows only ~0x10-byte
insertions there across b1→GM, so that path is **not** where the bulk of the fix landed.

---

## 7. Round 4 — the fix is a named hardening sweep in `b2 → b4`

Method: the step that carries a fix also carries its new strings. Diffing the `__cstring`
tables per step (`difflib` over NUL-split strings) names exactly what each step did:

| step | added strings | character |
|---|---|---|
| b1→b2 | +22 | `MCTFEnableGating`/`MCTFEnableFeedback`, DMV2 LoRes/HiRes input validity asserts |
| **b2→b4** | **+68** | **the kernel-memory hardening sweep (below)** |
| b4→b5 | +17 | MCTF feature work (`MCTFGatingType`, `MCTFPreFiltAdjType`, `AVE_CHM_GetMCTFOutBuf`) |
| b5→b8, b8→GM | 0 | nothing (b8→GM was BTI only) |

**The b2→b4 sweep is the fix step.** It adds explicit overflow validation to the *entire*
family of kernel-facing buffer-size calculators, plus four state-consistency checks. Verbatim
added strings (each with an accompanying `assert`-style guard string):

*Overflow guards on ~22 buffer-size calculators* — `AVE_CalcBufSizeOfMBInputCtrl`,
`…OfCodedData`, `…OfMBStats`, `…OfStaticAreaCBP0Cntr`, `…OfColoFwDataInfo`, `…OfDPB`,
`…OfColocated`, `…OfLRB`, `…OfHSCOutput`, `…OfLFSOutput`, `…OfLRSOutput`, `…OfSrcNeighborInfo`,
`…OfSTFSrcNeighborInfo`, `…OfSrcNeighborPixel`, `…OfSrcNeighborData`, `…OfSrcNeighborFwData`,
`…OfSrcNeighborAboveFltPixel`, `…OfSrcNeighborLeftInfo`, `…OfSrcNeighborLeftPixel`,
`…OfEntropyCoding`, `…OfEntropyCodingHeader`, `…OfMCTFOutput` — each with logs
`%s | size overflow %d %d %d %lld`, `%s | pixel area overflow …`, `%s | DPB size overflow …`,
`%s | LRB size overflow …`, `%s | HSCOutput size overflow …`, `%s | MCTFOutput size overflow …`,
and guards such as `size >= 0 && size <= 2147483647`,
`iLumaDataSize >= 0 && … && iTotal <= 2147483647`, `iSize >= 0 && iSize <= 2147483647`.

*Frame/dimension and slice bounds* — `%s | frame dimension out of range %p %lld %d %d %d %lld`
with `width >= 0 && height >= 0 && iPixelProduct <= 2147483647`; `%s | slice number is out of
range …` with `0 <= …sSliceMap.iNum && …sSliceMap.iNum <= ((32) < (256) ? (32) : (256))`
(this *replaces* the beta-2 assert form, which the step removed).

*State-consistency and firmware-command checks (the race candidates)* —
`%s | EncType mismatch with session %p %lld %d %d %d` with
`pInfo->sSessionCfg.sEnc.eType == pClient->eEncType`, and
`%s | invalid command slot %p %d %p %p %d %p %d [0, %d)` with
`0 <= fwCmdSlot && fwCmdSlot < (AVE_Cmd_Max + (((3 + 2) + 2 + 5 + (2 + 1)) * ((2) < ((63 + 1)) ? (2) : ((63 + 1)))))`.
Also `invalid LRMERC result in direct encode mode`, `invalid L%d%c ref firmware buffer in
direct mode`, `invalid L%d%c low res ref firmware buffer in direct mode`.

**Why this is almost certainly the advisory's AVEVideoEncoder fix set.** These are exactly the
kernel-facing size/state paths the campaign spent many epochs attacking: the AVE daemon's
`PrepareMBInputCtrl` memcpy is sized by `AVE_CalcBufSizeOfMBInputCtrl(session dims)` (FINDINGS
v132), and the campaign's own notes recorded the kernel-side `saMBInputCtrl[i]` validation.
CVE-2026-65410 (*"The issue was addressed with improved checks"*) and CVE-2026-84616
(*"A type confusion issue was addressed with improved memory handling"*) map onto the overflow
guards; **CVE-2026-84607** (*"A race condition was addressed with improved state management"*,
kernel privileges) maps onto the **state-consistency additions** — the encoder-type-vs-session
check, the firmware command-slot bounds check, and the **`AVE_SwC` object growing 0x80 bytes**
in this same step (a state/command-slot block, not a lock: no lock/unlock call was added
anywhere in the cycle — see §6.2).

**Where the new checks live in the GM binary (verified by localising their format strings):**
all three state/dimension checks resolve into one per-frame validation function,
**`sub_fffffff0087348a8` [0xfffffff0087348a8–0xfffffff00873508f]**, 55 basic blocks,
`int64_t(void* arg1, int64_t arg2, void* arg3)` — `frame dimension out of range` log at
`0xfffffff008734afc`, `EncType mismatch with session` log at `0xfffffff008734e6c`; the
`invalid command slot` log is at `0xfffffff0087aa018`. Reading the guard branches (rather
than the log-argument marshalling) and comparing against the homologous region in beta 2 is
the remaining verification step.

### 7.1 Correction — which checks are genuinely NEW (string-presence control)

Diffing added strings alone overstates the change, because a *re-worded* check also shows up as
an added string. Running the same substring search against the **pre-fix b2 binary** separates
the two:

| check | b2 (pre-fix) has… | verdict |
|---|---|---|
| `AVE_CalcBufSizeOf*` **size overflow** guards | only 3 `overflow` strings (`PS data overflows`, `LOG OVERFLOW`) | **GENUINELY NEW** (13 in b4: `DPB`/`LRB`/`HSCOutput`/`MCTFOutput`/`size`/`pixel area` …) |
| `iPixelArea >= 0 && iPixelArea <= 2147483647`, `width >= 0 && height >= 0 && iPixelProduct <= 2147483647` | absent | **GENUINELY NEW** (integer-overflow guards on pixel area / w·h) |
| `EncType mismatch with session` (`…sEnc.eType == pClient->eEncType`) | absent (only `encType not recognized`, `GBufSize: … encType: …`) | **GENUINELY NEW** — the only new *state*-consistency check |
| `invalid command slot … [0, %d)` | **present as `invalid firmware command buffer slot …`** | **PRE-EXISTED** — b2→b4 only *re-worded/upgraded* the message; the slot bound is not new |
| `frame dimension out of range …` | **present** (`%d %d %d`) | **PRE-EXISTED, extended** — the richer `%p %lld %d %d %d %lld` form is new |

This revises the round-4 wording: the firmware **command-slot check pre-existed** (different
message), so it is *not* an 84607 candidate. The genuinely new items are (a) the family of
**size/pixel-area overflow guards** and (b) exactly one new **state-consistency** check,
**`EncType mismatch with session`**. Alignment corroborates the scale: b2→GM functional growth
is **+0x43dc** in 141 insertion events, but only **8 bytes** of it land inside the per-frame
validation function `sub_fffffff0087348a8` (`0xfffffff008734b04`, `bl` + `cbz`) — so that
function was largely *edited in place*, not grown.

**Best-supported 84607 reading (still STRONG, not proven):** *"improved state management"* =
the new **encoder-type-versus-session consistency check**, which makes a per-frame command
reject when the client's `eEncType` no longer matches the session's — i.e. exactly the
state that a racing reconfigure/teardown could desynchronise. The overflow guards remain the
better fit for CVE-2026-65410 (*improved checks*) and CVE-2026-84616 (*improved memory
handling*).

### 7.2 The guard itself — located in GM, absent pre-fix

Targeted scan of GM `sub_fffffff0087348a8` for compares and encoder-type field loads:

```
0xfffffff008734d14  ldr w8,  [x22, #0x58]     ; client  eEncType
0xfffffff008734d18  ldr w9,  [x19, #0x270]    ; session sSessionCfg.sEnc.eType
0xfffffff008734d1c  cmp w8, w9                ; <-- the new state-consistency guard
0xfffffff008734e2c  ldr w9,  [x19, #0x268]    ; (log-marshalling counterpart below)
0xfffffff008734e30  ldr w10, [x22, #0x58]
0xfffffff008734e34  ldr w11, [x19, #0x270]
```

In the **homologous beta-2 region** (`0xfffffff00873ffa4` + the same span) there is **no
`[xN,#0x58]` load anywhere** and **no register-versus-register compare of two loaded fields** —
every compare there is against an immediate (`cmp w8,#1/#2/#3/#4`, `cmp w9,#0x12d`, …); the one
register compare present (`0xfffffff008740338 cmp w8,w21`) is a normalised 0/1 construct fed by
`csinc`, not a field-vs-field consistency test. So at the site where GM now rejects on an
encoder-type/session mismatch, the pre-fix build never even loads the client's `eEncType`.

**Assessment:** the new guard is the strongest CVE-2026-84607 candidate — it is the only new
*state*-consistency check in the fix step, and its failure mode (a frame carrying one encoder
type while the session's type has moved on) is exactly what a racing reconfigure/teardown
produces. **Status: PROVEN that the guard is new (b2 lacks it, GM has it, 8 bytes inserted at
`0xfffffff008734b04`); STRONG (not yet proven) that it is CVE-2026-84607 specifically** —
still open: whether the mismatch path *rejects* the frame or only logs, what writes
`sEnc.eType` concurrently, and whether that writer shares the client lock at `this+0x158`.

### 7.3 The guard is functional, not log-only

```
0xfffffff008734d14  ldr w8,  [x22, #0x58]      ; client  eEncType
0xfffffff008734d18  ldr w9,  [x19, #0x270]     ; session sEnc.eType
0xfffffff008734d1c  cmp w8, w9
0xfffffff008734d20  b.ne #0xfffffff008734dfc  ; MISMATCH -> diverted, normal path skipped
0xfffffff008734d24  mov x0, x1                 ; MATCH:
0xfffffff008734d2c  bl #0xfffffff008733654    ;   normal frame-processing call
0xfffffff008734d30  cbz w0, #0xfffffff008734e74
```

A mismatched encoder type **never reaches the normal processing call** — it takes a separate
block, while a match proceeds into `sub_fffffff008733654` and consumes its result. So the new
check **gates frame processing** (it is not a log-and-continue assertion). Remaining open:
whether the divert block returns an error or a silent skip (follow `0xfffffff008734dfc`), and
the concurrent writer of `sEnc.eType` (the race dimension).

### 7.4 The race dimension: the checked field has ONE writer, and it takes no lock

Scanning the whole GM kext for stores to the session-type pair:

| field | writers in the entire kext |
|---|---|
| `[xN,#0x270]` (the `sEnc.eType` the guard reads) | **exactly 1** — `0xfffffff008737f98 str w22, [x19, #0x270]` |
| `[xN,#0x268]` (written as a pair with it) | 6, incl. `0xfffffff008737f94 str w27, [x19, #0x268]` (the same site pair) |
| `[xN,#0x58]` (the client-side value) | 64 — generic offset, so the client field cannot be identified by offset alone |

In the writer's own body (`0xfffffff008737c00`–`0xfffffff008738400`) **neither the lock helper
`0xfffffff0086e5594` nor the unlock helper `0xfffffff0086e55d4` is called** (0 each); its callees
are the AVE logging family (`0xfffffff0087ed13c`/`…d184`/`…d1bc` ×7 each, the hottest stub
`0xfffffff0088928c8` ×7). So the field the new guard validates is written on a path that does
**not** hold the client lock at `this+0x158` — i.e. the reader and the writer live in different
locking domains.

That is exactly the shape of *"a race condition was addressed with improved state management"*:
rather than retro-fitting a lock, the fix **validates the state at the point of use** and diverts
the frame when the encoder type no longer matches the session. **Caveat: only the writer's own
body was scanned — a caller further up could still hold the lock.** Verifying the writer's caller
chain is the last remaining step for this front.

### 7.5 Writer chain is lock-free (two levels)

Following the sole writer of the checked field up its call chain:

| level | function | range | BBs | lock/unlock calls |
|---|---|---|---|---|
| writer | `sub_fffffff008737874` | `0xfffffff008737874`–`0xfffffff008738d8f` | 155 | **0** |
| its **only** caller | `sub_fffffff008739440` | `0xfffffff008739440`–`0xfffffff008739eef` | — | **0** |

(callsite `0xfffffff008739b34`; `bn_function_callers` reports exactly one caller.)

So the field the new per-frame guard validates is written by a chain that holds no client lock,
while the guard reads it in the per-frame path — a genuine reader/writer locking asymmetry, i.e.
the shape of *"a race condition was addressed with improved state management"*.

**Residual caveats (state them, do not bury them):**
1. The lock/unlock helper identity (`0xfffffff0086e5594` / `0xfffffff0086e55d4`) is inherited from
   the prior campaign's identification of the beta-1 equivalents; if those are not in fact the
   `IOLock` wrappers, the "lock-free chain" conclusion weakens. Independent confirmation of the
   helper's callee (`__auth_stubs` target at `0xfffffff0088922e8` / `…2f8`) would settle it.
2. One further caller hop above `sub_fffffff008739440` was not walked.
3. Attribution of the guard specifically to CVE-2026-84607 (rather than 65410/84616) still rests
   on the *"state management"* wording plus the race shape, not on a vendor statement.

### 7.6 Residuals closed

1. **The two helpers really are a lock/unlock pair** (structural proof, independent of symbol
   names): of the **152** callsites of `0xfffffff0086e5594`, **148 (97%)** have a call to
   `0xfffffff0086e55d4` within the following 0x600 bytes — i.e. take-then-release inside the
   same function, which is the lock/unlock idiom. This corroborates the prior campaign's
   identification and removes the "if they aren't the IOLow wrappers" caveat.
2. **The caller chain terminates at an indirectly-dispatched function.**
   `sub_fffffff008739440` has **zero** static callers (`bn_function_callers` → none), i.e. it
   is reached by vtable/IOKit dispatch, which BN cannot see for these binaries. So the
   writer→caller pair is the whole statically visible chain, and it holds no lock.

### 7.7 Verdict

Within `com.apple.driver.AppleAVE2`, the only change in the fix step `b2 → b4` that is
*state* management (rather than an added bounds check) is the new per-frame guard comparing the
client's `eEncType` against the session's `sEnc.eType`, which **diverts the frame** on mismatch,
did **not exist pre-fix**, and whose checked field is written by a **lock-free** chain. Apple's
other two AVEVideoEncoder entries are worded differently — *"improved checks"* (CVE-2026-65410)
matches the overflow-guard family, and *"type confusion … improved memory handling"*
(CVE-2026-84616) matches neither, so it must live elsewhere. By wording and by race shape,
**the state guard is CVE-2026-84607.**

**Remaining item that cannot be closed from these artifacts:** Apple does not publish a
per-CVE code mapping, so "this guard = 84607" is a convergent inference (fix step + wording +
race shape + absence pre-fix + lock-free writer), not a vendor statement. The one unexplored
*component* of "AVEVideoEncoder" is the userspace `ave.videoencoder` /
`AppleVideoEncoder.bundle`, whose pre-fix copies sit in the beta root `.dmg` dyld shared caches
(~243 MB members).

### 7.8 Caveat on the offset-based evidence (found while adversarially re-checking)

The claim "beta 2 never loads `[xN,#0x58]` at that site" is weaker than it looks: **`0x58`, `0x268`
and `0x270` are generic struct offsets**. Counted across each whole kext:

| build | `str` to {0x58,0x268,0x270} | `ldr` from them |
|---|---|---|
| beta 2 (pre-fix) | 74 | 346 |
| GM (fixed) | 73 | 347 |

So offset co-occurrence proves nothing by itself, and beta 2 could in principle perform an
equivalent comparison at *different* offsets if the session/client blocks were laid out
differently before the fix step. What remains **solid** is: (i) the check's string
`EncType mismatch with session` is genuinely absent from beta 2 and present from beta 4 on
(whole-table diff); (ii) in GM that string's function contains a two-field compare that gates
the normal frame-processing call; (iii) the fix step is b2→b4. What is **not yet solid** is that
beta 2 has no functionally equivalent guard. Adversarial verification of exactly this is in
flight (`analysis/ave84607_ADVERSARIAL.md`).

### 7.9 METHODOLOGICAL CORRECTION (round 15) — the beta-2 side of the comparison is unreliable

The "beta 2 never loads `[xN,#0x58]` at that site" evidence (rounds 6–7) was obtained by mapping
the GM address through the LIS-chained alignment and reading a beta-2 window at the mapped
offset. **That mapping is unsound.** Re-reading it in round 15, the mapped beta-2 address
`0xfffffff0087405a0` lands in **PAC-signing code**
(`eor x16,x8,x1 ; tst x16,#-0x40000000000000 ; b.eq … ; movk x1,#0xc8a2,lsl#48`) — an
unrelated function. The alignment's "nearest chained anchor" can therefore be far from the
target, so any beta-2 conclusion drawn from a mapped address must be discarded.

A string-anchored retry (locating beta 2's own `frame dimension is out of range` ref and scanning
±0x300 for register-vs-register compares) returned **0 such compares in both builds** — but the
compare is not in that window in either, so the test does not discriminate either.

**Consequence for the finding:** the claim that the EncType guard is *absent pre-fix at code
level* is **NOT established**. What survives independently of address mapping:
1. the string `EncType mismatch with session` is genuinely absent from beta 2 and present from
   beta 4 onward (whole-`__cstring`-table diff);
2. in GM that string's function contains the two-field compare, and the mismatch path **diverts**
   the frame (quoted instructions, §7.3);
3. the fix step is `b2 → b4`;
4. the compared field's writer chain holds no lock (§7.5), and the helpers are a real lock/unlock
   pair (§7.6) — both measured entirely within GM.

**To redo properly:** get beta 2's function boundaries (BN can analyse the beta-2 kext, or use a
prologue scan), then examine the *beta-2 function that contains the same log family* for a
two-field compare gating its own processing call. Alternatively diff whole functions with a
proper function-boundary alignment rather than nearest-anchor mapping.

**Round-16 follow-up:** a byte-match attempt to find beta 2's copy of the *protected* function
(GM `sub_fffffff008733654`, key = 16 bytes at +0x20) produced **one** 16-byte hit in beta 2
(`0xfffffff00873e774`) with **zero** `bl` call sites — i.e. almost certainly a coincidental match
on a generic compare idiom, not the function. Also consistent with the possibility that the
protected helper is itself **new in the fix step**. Inconclusive; do not read it as evidence
either way.

**Attribution caveat (unproven):** the *step* and the *check set* are PROVEN; assigning 84607
specifically to the command-slot/EncType state additions (rather than to one of the overflow
guards, or to the userspace plugin) is a STRONG hypothesis, not yet proven from the code.
The userspace side (`ave.videoencoder` / `AppleVideoEncoder.bundle`) has **not** been diffed
across the fix window — its pre-fix copies live in the dyld shared cache inside the beta
root `.dmg` members (243 MB each), not in the kernelcache.

---

## 8. Next steps



1. **Bisect the fix step.** Fetch the `b2` (`24A5370h`), `b4` (`24A5390f`) and `b5`
   (`24A5408d`) kernelcaches (each ~23 MB by range fetch, same technique) and align each
   against GM to find which step changed the client-state/delayed-surface/EUC code.
2. **Finish the masked site diff.** Mask conditional-branch targets and the log line-number
   immediates, then diff every anchor (delayed-surface family, `AttachEUC`/`DetachEUC`/
   `ReleaseEUC`, `check state`, `wrong state`, `NumOfOpenClients`/`concurrent_mode`).
   The `+0x10` client-struct growth is the thread to pull: find which field was added and
   what code reads/writes it.
3. **Reconcile with the 4-agent kext wave** (client lifecycle, delayed surfaces, EUC,
   UC dispatch) — their reports describe the *GM* (fixed) shape of these paths, which is
   what we need to compare against the beta-1 shape.
4. **Obtain a pre-fix AVE plugin** if the plugin is implicated: the beta-1/2 dyld shared
   cache (inside the root `.dmg` member of the beta IPSW) is the only source.

---

## 7. Reproduce

```bash
# baselines (range fetch; ~23 MB each, no full IPSW download)
python3 scripts/ds_ipsw_range.py <beta8 url> --get kernelcache.release.v59 --out /tmp/beta8/kc
python3 scripts/ds_ipsw_range.py <beta1 url> --get kernelcache.release.v59 --out /tmp/beta1/kc
ipsw kernel dec <kc> && ipsw kernel extract -a -o <out>/kexts <kc>.decompressed

# analysis
python3 scripts/ds_ave_align.py /tmp/beta1/kexts/com.apple.driver.AppleAVE2 \
        /Users/pauyedin/24A435__iPhone17,5/kexts/com.apple.driver.AppleAVE2
python3 scripts/ds_ave_sitediff2.py            # BTI-aware site diff (b1 vs GM)
python3 scripts/ds_ave_atomics.py              # proves zero atomics in GM
python3 scripts/ds_bn.py bn_function_list '{"start":"0xfffffff008876c00","length":4096}'
# Binary Ninja view_1 = GM AppleAVE2 (base 0xfffffff00729c990, 3033 functions)
```
