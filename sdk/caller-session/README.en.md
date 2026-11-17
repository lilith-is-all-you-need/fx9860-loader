# Caller session library

This C99 library coordinates **cooperative business-state recovery** for one
caller A and one target B. It is suitable for source integration in FxStudio.
It does not relocate binaries, retain A's stack/heap, install an exception
handler, or turn the current `FlashLd.g1a` into a callable backend.

The control library and its host fault tests are implemented. A production
calculator backend providing the capabilities below is still required. Do not
advertise the library as general A → B → A support until that backend and its
hardware acceptance tests pass. No current FlashLd capability is assumed.

## Add to a source project

```cmake
add_subdirectory(path/to/sdk/caller-session caller-session)
target_link_libraries(my_addin PRIVATE FxStudio::CallerSession)
```

Include `fx_caller_session.h`. Supply an `fxcs_app` with pause, serialize,
reinitialize, restore and resume hooks, an audited `fxcs_backend`, and a
caller-owned working buffer. The library allocates no heap memory and performs
no direct OS or file calls. The working buffer needs 96 bytes plus the maximum
serialized state, up to 65,536 state bytes. It is not a surviving RAM reservation:
the committed snapshot lives in the backend's transactional storage.

`examples/caller_flow.c` shows the call sequence. It intentionally has no fake
FlashLd backend. An unsupported backend must return insufficient capabilities;
`fxcs_prepare` then rejects the request before pause, serialization, or storage.

## Implemented lifecycle

1. `fxcs_prepare` checks capabilities and system-wide call depth, pauses A,
   serializes its business state, and atomically commits the snapshot. The
   caller supplies a nonzero session ID; the backend rejects reused IDs and
   atomically claims the one allowed call slot.
2. `fxcs_handoff` transfers to B. A real hardware backend normally does not
   return on A's old stack. An asynchronous backend may return
   `FXCS_TRANSFERRED`; A must yield immediately and may not resume normal work.
   A reported handoff error must mean the transfer never happened and A's RAM
   remains intact; the controller consumes its prepared snapshot and resumes A.
3. On a verified normal exit, A is reinitialized, its business snapshot is
   restored, the durable record is consumed, and A is resumed.
4. On direct MENU return, `FXCS_MENU_RESTORE_CALLER` follows the same recovery
   path after the backend has terminated B. `FXCS_MENU_RESUME_TARGET` asks the
   backend to resume B and retains A's snapshot until B exits.
5. A verified different foreground application or OS restart discards the old
   session without restoring A or B. Crash/reboot state recovery is not promised.

The backend's resident event proof, not an application-provided event number,
must distinguish direct MENU return from a cold start or another application.
Boot ID, session ID and caller ID bind each stored snapshot. Corrupt, mismatched,
or unverified records never invoke application restore hooks and are retained
for diagnosis. CRC detects accidental corruption; it is not authentication.

For `MENU_RESUME_TARGET`, the backend must preserve B's full required runtime
state. It must route MENU return before A's CRT overwrites B's RAM, or have a
complete restorable B snapshot. Merely reinitializing A and loading its business
data cannot provide this capability. Similarly, returning to A requires a
resident trampoline to restore A's mapping and enter its recovery path safely;
an ordinary C function return into overwritten memory is invalid.

## Backend obligations

| Operation | Required behavior |
| --- | --- |
| `inspect` | Read-only capability check, verified boot identity, global active depth, reused-ID rejection |
| `commit` | Atomic durable record and single-session claim; failure preserves previous committed contents |
| `read` | Read a complete record or fail; never silently truncate |
| `consume` | Compare the complete ticket and atomically remove only that record; failure preserves it |
| `handoff` | Actually establish the accepted target lifecycle; a failure means caller RAM/resources are still recoverable by resume |
| `verify_event` | Prove ticket/boot/foreground continuity and appropriate caller mapping; target resources already stopped when recovering A |
| `resume_target` | Restore the target's actual continuation and runtime, not merely restart its `main` |

All required capabilities must be present. The controller rejects nested calls
before changing state; `commit` must also arbitrate competing claims to close the
check/commit race. Backend tables are compiled source interfaces, not executable
plugins loaded from an untrusted profile.

Atomic storage is a backend responsibility because the available calculator file
APIs and lifecycle need validation. Do not equate a successful ordinary file write
with durable atomic commit. A backend may use two preallocated records with
generation/checksum/commit markers, but must test interrupted writes and stale
selection. Serialized business data must contain portable values, not raw stack
addresses, live OS handles, timer pointers or allocator metadata.

## Failure and retry

- Save/commit failure resumes the still-live A and does not launch B. A failing
  pause hook must undo its own partial pause before returning an error.
- A prepared call can be cancelled. If record consumption fails, A stays paused;
  retry `fxcs_cancel` after fixing storage. It is not safe to silently continue.
- Failed restoration retains the record. `fxcs_recover` can be retried after a
  verified event. Reinitialize/restore must be idempotent and must not duplicate
  external effects: a crash or consume failure can cause restore to run again.
- Backend failure while resuming B retains A's record. The resident adapter must
  provide a safe failure route; the library cannot repair an invalid VBR/MMU.
- Run another OS application or reboot only after the resident backend has safely
  relinquished its mappings/resources. Record invalidation alone is not cleanup.

## Validation

`python -m unittest discover -s tests -p test_caller_session.py -v` compiles the
library with the available host GCC/Clang and runs nine lifecycle groups plus
100 single-byte corruption cases. Tests cover both MENU policies, fresh caller
RAM on recovery, pre-mutation capability/nesting refusal, reentry, save/commit/
handoff/consume failures, retry, old-boot rejection and foreign-app invalidation.

Alternatively enable `FXCS_BUILD_HOST_TESTS` in a host CMake build. These are
host contract tests, not calculator backend or hardware validation. See
`VALIDATION.json` for the exact scope.
