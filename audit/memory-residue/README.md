# BurnerNet Memory-Residue Audit

This is a dedicated Windows x64 Release harness for manually checking
BurnerNet, libcurl, and OpenSSL memory residue. It is intentionally separate
from the consumer examples.

Visual Studio can open this directory directly as a CMake project. Select either
the `maximum-ghost` or `no-ghost` configure preset.

## Build and run

From a Visual Studio Developer PowerShell:

```powershell
cmake --preset maximum-ghost
cmake --build --preset maximum-ghost
.\out\build\maximum-ghost\bin\BurnerNetMemoryAudit.exe
```

Control build:

```powershell
cmake --preset no-ghost
cmake --build --preset no-ghost
.\out\build\no-ghost\bin\BurnerNetMemoryAudit.exe
```

The two builds use the same Release workload, hardened imports, obfuscation,
diagnostic-off mode, loopback protection, canaries, and ten-second idle window.
Only Maximum Ghost allocator hooks differ.

Scan writable process memory during the idle window for:

- `burnernet-audit-url-canary-48291`
- `burnernet-audit-token-canary-73915`

The harness runs until `Ctrl+C`.

## Static preflight

```powershell
$binary = ".\out\build\maximum-ghost\bin\BurnerNetMemoryAudit.exe"
dumpbin /imports $binary | Select-String "libcurl|ws2_32|bcrypt|crypt32"
rg -a "TlsVerificationFailed|ConnectedPeerGuard|burnernet-audit-(url|token)-canary" $binary
```

Both searches should return no matches.

## Interpreting the comparison

| Result | Meaning |
| --- | --- |
| Canary appears only without Maximum Ghost | Allocator hooks provide measurable cleanup value |
| Canary appears in neither build | No residue was observed under this workload |
| Canary appears in both builds | Investigate hook coverage and the address owning the match |
| Token is absent but URL remains | Credential cleanup succeeded; URL handling needs investigation |

This is not a production bootstrap recipe. The harness only checks that its
staged DLL is a regular file; production applications must authenticate their
own dependencies.
