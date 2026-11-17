# Source library regression guest

This tiny source-integrated payload links `FxStudio::LargeRuntime`, binds the
provided MapApi, reads and verifies the first word of every configured image page,
reports completion through the stage callback, unbinds, and returns normally.
It stays in the loader's VBR world; it does not install a new gint world or claim
to test interrupt-driver replacement.

Build Debug then Release with FxStudio. The generated G1A is a compiler transport
container for the tests, **not a standalone calculator app**. Do not install that
container directly; its entry expects the loader's third argument. Use
`tests/make_source_guest.py` to wrap its body in the versioned source-runtime
header, or `tests/run_source_guest.py` for an isolated firmware-assisted emulator
test. All profile page counts are derived from the actual image header; no 699
page constant is compiled into this guest.

The runtime test checks normal return, successful page checks, zero spare table
entries and release of the loader allocation. It only reads debugger memory
after the actual guest has finished; it never patches registers or guest memory.
The source and generated page patterns are authored test material. No proprietary
firmware or third-party program binaries belong in the repository.
