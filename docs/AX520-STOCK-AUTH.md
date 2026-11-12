# AX520 stock authentication control flow

Static analysis only, 2026-11-12. No stock binary was executed, no live settings changed, and no certificate, private key or decoded identity data was extracted. Addresses below are ARM ELF virtual addresses; stripped functions require Thumb disassembly (`objdump -M force-thumb`).

Analyzed backup SHA-256: `84e852d1da60dcca0f46c2a517419560d62b452d58093d59b590e6a021c05010`.
The original backup is retained outside this repository. No firmware or proprietary library is included here.

| File within customer partition | SHA-256 |
| --- | --- |
| `app/libiap_new.so` | `19326c5b73c61fd5a604d114ad49035a3730c7d12bfacaef165f7048e8f42e53` |
| `app/lylinkapp` | `55afbb890397b41d3393f1a98a82a5d425fb5fb78b97431f8dad48990ce509f2` |
| `app/ly_testcp` | `ffe245a28de3dba0bc115f08ea0ecad2d80a8b1ea1cab9a2902524375167339b` |

The [experimental external MFi provider](EXTERNAL-MFI.md) supplies a host integration point only. It does not implement or validate the stock device's provider.

## Verified selector and dispatch

In `customer/app/libiap_new.so`:

- Export `SetiAPI2CAddr` at `0x708c` ignores its original first argument, forwards argument 2 as the address and argument 3 as the path into internal selector `0x652c`, then calls initializer `0x65bc`.
- At `0x6558` selector `0x652c` calls `strcmp(path, "ly_iap")`. Equality writes global auth mode **2** at `0x6562–0x6564`. Other paths write mode **1** at `0x6588–0x658a` and invoke hardware setup `0x4e34` with the provided address/path.
- Initializer `0x65bc` invokes hardware initialization only for mode 1; mode 2 returns zero without that call.
- Export `AuthDeviceCreateSignature` at `0x65dc` dispatches mode 2 to `0x6378` and other modes to hardware function `0x4f14`.
- Export `AuthDeviceCopyCertificate` at `0x6600` dispatches mode 2 to `0x6470` and other modes to hardware function `0x546c`.

Thus `ly_iap` is an explicit mode selector string. It is not opened as a device by these selector instructions.

## What the software branch does

- Signing function `0x6378` transforms an embedded 32-byte input into a temporary buffer via helper `0x633c`, allocates its output, and invokes internal helper `0x628c`. That helper copies a 32-byte input, performs internal computation through `0x615c`/`0x6228`, and copies two 32-byte result components to the output buffer. No external signing service or `/dev/ly_encry` call occurs in the displayed software entry routine.
- Certificate function `0x6470` sets output length to **607**, allocates a fresh buffer, and invokes internal helper `0x633c` to populate it from embedded data. It returns zero on its normal path and minus one on allocation failure.
- These are concrete software operations inside the library. Their existence does not prove stock selected this mode in a particular boot, that the identity is valid, or that an iPhone accepted it.
- The entry arguments have the expected shapes `AuthDeviceCreateSignature(digest, digest_len, &output, &output_len)` and `AuthDeviceCopyCertificate(&output, &output_len)`. Fresh allocation is visible. ABI types, constructor requirements and safe ownership must still be checked before any wrapper is executed.
- The inspected signing entry logs the supplied digest length but shows no rejection before the helper reads exactly 32 input bytes and writes 64 result bytes. A future wrapper must enforce the 32-byte input contract, validate advertised output length, and serialize calls because internal global scratch storage is visible. These are implementation prerequisites, not evidence that a wrapper has been tested.
- The library is 32-bit ARM with uClibc dependencies `libstdc++.so.6`, `libgcc_s.so.1`, `libc.so.0`, plus ELF init/init-array entries. It cannot simply be loaded into Cruiser's native 64-bit process.

No embedded credential bytes were inspected or recorded. No implementation or service wrapper has been added.

## `/dev/ly_encry` detection in `ly_testcp`

Function `0x1b968` performs a local probe:

1. Opens `/dev/ly_encry` with flags zero (read only) at `0x1b9ac`.
2. Sends ioctl **`0x40046551`** at `0x1b9d6`. The supplied word is the bitwise complement of a locally obtained value.
3. Tests whether the returned word equals the original value plus one at `0x1ba04–0x1ba20`.
4. If successful, returns **1** at `0x1ba5e`. If unsuccessful, calls the hardware test at `0x1b6f4` for addresses **0x10**, then **0x11** (`0x1ba4c–0x1ba56`).

Main calls this function at `0x12b0e`, stores the result at `0x12b12`, and logs it as the MFi state. Therefore a positive `mfi State`/`bLyChip` result can originate from this local driver probe. It is not an end-to-end phone authentication result. The driver's implementation has not been independently analyzed in this pass; the caller's test does not establish what hardware, if any, lies behind the ioctl.

## Selection in `lylinkapp`

- Its `findMfi` code opens `/dev/ly_encry` at `0x18796`, issues the same ioctl at `0x187b2`, and checks the same reply relation.
- Success follows `0x188a8–0x188ce`, copies the literal `ly_iap` to the stored authentication path at `0x188de–0x188fa`, and sets the stored address to **0x20** at `0x188fe`.
- Failure takes the I2C path from `0x187e4`. It gets `LY_MFI_I2C_BUS`, constructs `/dev/i2c-%s`, and probes 0x10/0x11 using register 0x04 writes and four-byte reads. This is an active hardware probe; do not execute it merely to inspect status.
- The final diagnostic line is exactly `findMfi end ADDR_I2C = %x,PATH_I2C=%s`.
- Bluetooth and Wi-Fi iAP setup both pass the selected address/path to `SetiAPI2CAddr` at `0x18464` and `0x18230` respectively.

This establishes an actual static path from the successful driver probe to the software auth selector. It does not establish that the live unit took it.

## Runtime prerequisites and existing logs

The preserved `lyLink.sh` starts `logwrapper ly_testcp -f=2`, `rcpservice -k1`, `lyUpdate.sh`, `lyLoadModule.sh`, then waits up to about five seconds for `/tmp/lyrcpok` before starting `lylinkapp -w`. Relevant environment defaults in `/etc/profile` are `LY_MFI_I2C_BUS=2`, `LY_ENCRYPT_I2C_BUS=1`, and `IPADDR=192.168.50.100`.

The rootfs includes `/sbin/logcat` and `/sbin/logwrapper`. The existing web CGI log collection uses `logcat -v threadtime -d` along with other data and writes `/tmp/log.gz`; the website's Submit action additionally uploads to the vendor. Prefer a local read-only logcat query over that CGI or Submit action.

Once a shell is reachable, useful **allowlisted existing log markers** are:

```text
findMfi end ADDR_I2C = ... PATH_I2C=...
g_authMode:...
bLyChip = ...
mfi State=...
AUTHENTICATION_SUCCEEDED
AUTHENTICATION_FAILED
```

A bounded shell query can run `logcat -v threadtime -d` with output filtered on-device for those markers; never transfer an unfiltered dump. Preserve timestamps and process tags. Exclude lines containing credential/certificate/key/challenge/signature data if logging is unexpectedly verbose.

Interpretation:

- `PATH_I2C=ly_iap` and `g_authMode:2` establish software mode selection in that logged process/session.
- `bLyChip` or `mfi State` alone establish only a local probe result.
- The library contains exact received-message markers `--[iDevice -> Acc]AUTHENTICATION_SUCCEEDED----iAP2 Connection Pass--` and `--[iDevice -> Acc]AUTHENTICATION_FAILED---iAP2 Connection Fail-----`. A timestamped live occurrence is evidence of the corresponding iAP2 event, subject to checking its process/session context.
- An iAP2 success event still does not by itself verify the subsequent CarPlay/AirPlay authentication exchange, video, audio, touch or reconnection.
- Absence of a marker is inconclusive if the ring buffer rotated or that component's logger is disabled.

Safe prerequisites to read first are process presence, node existence, the expected stock library checksum, and `/tmp/lyrcpok`/`ly_author_*` marker **metadata only**. Do not rerun `ly_testcp`, force a mode, call the driver ioctl or execute a proposed signer wrapper before the runtime assumptions have been reviewed.


## ABI and startup safety follow-up

This section remains static analysis. An independent stock-library wrapper has **not** been implemented or executed.

### Constructors and per-process state

- ELF `.init` at `0x1b98` is a trivial return. The three init-array entries are `0x1fbd`, `0x1ed9`, and `0x1ee5`: frame/TM registration and two C++ iostream initialization stubs. Their reviewed call paths do not initialize authentication or open the MFi device. Fini-array entries `0x1f65`, `0x1ec1`, and `0x1ecd` perform matching runtime cleanup. This is evidence about these functions, not a guarantee about every dependency's loader behavior.
- The auth-mode global resolves through GOT slot `0x29f84` to DSO-relative address `0x2a31c`. Its initial byte is **1**, the hardware mode. A separate process loading this DSO gets its own state; it does not inherit the selection already made by the running `lylinkapp`.
- Calling `SetiAPI2CAddr` with the literal `ly_iap` directly selects mode 2 unconditionally. It does not rerun the stock `/dev/ly_encry` decision. Using it as a fallback after a failed or unverified device check would bypass the normal stock provider selection and is outside this proposed integration.
- No exported getter for the actual selected provider was found. A timestamped log can establish what a running process selected, but loading another process does not transfer that state. Reusing the dispatch inside the existing stock process would preserve the actual decision; such process integration is itself unimplemented and requires a reviewed mechanism. An independent helper would need an independently validated equivalent of the normal selection procedure, with explicit failure handling. Forcing mode 2 is not that procedure.

### Function shapes and ownership

ARM EABI call sites support these **inferred** C function shapes, with pointer and length values 32 bits in this binary:

- `int SetiAPI2CAddr(void *context, int address, const char *path)` — the inspected implementation ignores `context`, but this is undocumented behavior. Normal stock supplies a real iAP context. It also invokes initialization. Internal initializer `0x65bc` calls hardware certificate initialization at `0x5798` for mode 1, then overwrites the result with zero. Therefore a zero return from the setter does **not** prove initialization succeeded.
- `int AuthDeviceCreateSignature(const void *digest, size_t length, unsigned char **output, size_t *output_length)` — four register arguments. The software helper consumes 32 digest bytes and produces two 32-byte result components. The reviewed entry logs length without enforcing it. A future caller must validate exactly 32 bytes before invoking the software path and validate the resulting pointer and length before use. The signedness or typedef of the original length is not recoverable from these call sites alone.
- `int AuthDeviceCopyCertificate(unsigned char **output, size_t *output_length)` — two register arguments. The software implementation preassigns length 607, then allocates; allocation failure can therefore leave a nonzero length with a null pointer. Initialize both out parameters before invocation and check both afterward.

Ownership is confirmed by the library's normal callers: signer callback `0x6bb4` initializes output slots, calls the signing export at `0x6bc4`, passes the result onward, then calls the same runtime's `free` at `0x6bd8`. Certificate callback `0x6c04` follows the same pattern with calls at `0x6c14` and `0x6c28`. This does not justify passing allocated buffers across incompatible libc/architecture boundaries.

The binary declares ARMv7/Cortex-A7, Thumb-2/NEON and hard-float EABI, and depends on its uClibc/C++ runtime. Any eventual device-side process needs that compatible runtime. The proposed ABI is not a native AArch64 Cruiser ABI.

### Lifecycle and remaining blockers

- `DestroyiAP2` calls internal auth finalization at `0x7368` and then dereferences the supplied context. It is **not** a standalone safe null-context auth cleanup function. No exported auth-only finalize function was found. The software finalizer at `0x650c` is a logging routine; the general iAP lifecycle also manages mutexes, transport and session resources.
- The software helper uses global scratch state. Serialize any future requests and never race a change of provider against an active signature operation. Memory allocation and success return are not evidence that the phone accepted the result.
- No exported protocol-major query was found. A 32-byte digest and 64-byte signature shape are consistent with an elliptic-curve provider but are not sufficient by themselves to establish all advertised authentication metadata. That metadata and normal on-device behavior remain runtime validation requirements.
- Required live evidence is still: correct library hash on the current boot, the actual stock-selected mode/path in the running process, and phone handshake outcome. Inspect these before proposing process integration or an independent helper.
- No credential export, stock binary execution, mode forcing, duplicate `lylinkapp`, authentication service, or device mutation was performed for this report.
