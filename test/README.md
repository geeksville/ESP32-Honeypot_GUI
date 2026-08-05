# Native test harness

Builds the firmware's parsing logic on a normal machine so it can be fuzzed
under AddressSanitizer, without an ESP32 in the loop.

```bash
clang++ -std=gnu++17 -g -O1 -fsanitize=fuzzer,address,undefined \
        -I test/shim -I src -o /tmp/fuzz_shell test/fuzz_shell.cpp

/tmp/fuzz_shell test/corpus -rss_limit_mb=2048 -timeout=10
```

`shim/` is a small Arduino compatibility layer. Its `String` deliberately
reproduces the ESP32 core's *defensive* behaviour — clamping out-of-range
indices and returning `0` / `-1` / `""` rather than faulting. Substituting
`std::string` semantics would make the fuzzer report crashes that cannot happen
on the device.

`fuzz_shell.cpp` includes `hp_shell.cpp` rather than its header so the static
internals (`vfsResolve`, `extractUrl`, `doLs`) can be driven directly. Input is
treated as a session transcript: newline-separated lines fed in order, exactly
as `pumpTelnet` delivers them.

Last run: 655k executions, no crashes.
