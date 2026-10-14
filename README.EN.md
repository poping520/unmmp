# unmmp - nmmp VM bytecode recovery tool

[简体中文](README.md) | **English**

Recovers dex bytecode from native methods protected by [nmmp](https://github.com/maoabc/nmmp) dex-vm using Unicorn emulation.

Supports protected APKs for ARM32, ARM64, x86, and x86_64.

## Example output

![app-release-protect.png](test-apk/app-release-protect.png)

## Installation

```powershell
python -m pip install -r requirements.txt
```

Dependencies: Python 3 and Unicorn 2.1.4 or a later 2.x release.

Rebuilding dex requires Java. Standalone baksmali / smali jars are included.

Source: [smali v2.5.2](https://github.com/baksmali/smali/releases?page=2#release-v2.5.2).

| File | SHA256 |
|---|---|
| tools/baksmali-2.5.2.jar | d3116248cce4f82ec5a31eb7f95ee75daff42ddf6eed0ab573973dc53fbad2e5 |
| tools/smali-2.5.2.jar | 9544299578b16f771d8aa8eaefe0d3718ca03478c16f3c356f2fcf1366bfb116 |

## Usage

```powershell
python unmmp.py app.apk -o out
python unmmp.py app.apk -o out --prefer-abi armeabi-v7a
python unmmp.py app.apk -o out --skip-dex
```

- `--skip-dex`: write opcode mappings, method bodies, and recovery statistics without assembling dex.
- `--prefer-abi`: select a native library pair for the specified ABI. The default order is arm64-v8a, armeabi-v7a, x86_64, then x86.

Accepts an APK or an extracted directory containing dex files, libnmmp.so, and libnmmvm.so.

Reusing an output directory removes previous restored dex files, mappings, method bodies, summaries, error reports, and generated directories. work/, smali*/, and patched_smali*/ are reserved output directories. Input must be outside these generated directories and must differ from the output directory.

If recovery fails, partial restored dex files and the success summary are removed; diagnostics and intermediate files are retained. An explicit `--prefer-abi` uses only that ABI and fails if its library pair is missing.

## Output

- classes_restored.dex, classes2_restored.dex, etc.: restored dex files. Splitting to meet index limits may increase the number of files.
- opcode_mapping.json: the APK's opcode semantics mapping.
- opcode_aliases.json: variants merged by the compiler that require type information to distinguish.
- native_methods.json, lifted_bodies.json: method bindings and smali method bodies.
- recovery_summary.json: extraction, decoding, patching, output files, and validation statistics.
- work/: temporary dex files and partitioned smali used during assembly.
- smali/, patched_smali/: original and patched smali, with corresponding suffixes for multiple dex inputs.

Some mapping entries use representative semantic names. The final return, invoke, and move instructions are selected using method declarations and register types.

## How it works

[nmmp protection and unmmp recovery explained (Chinese)](intro.html)

nmmp executes method bytecode through a native VM and rewrites opcode values and symbol reference indices. unmmp emulates the target libraries with Unicorn and recovers this information from their behavior:

1. Intercept JNI method registration and VM entry to capture method bindings, bytecode, exception tables, and register layouts.
2. Run controlled instructions in the target interpreter. Compare register changes, branches, and JNI calls with Dalvik semantics to identify opcodes.
3. Call the target library's resolver to recover field, method, type, and string references. Combine them with dex metadata to generate smali, replace native methods, and rebuild dex.

Recovery uses information from the APK itself, without a fixed opcode mapping. Assembly handles string and index limits, then validates the output dex files and restored method bodies. Unrecognized calls or unresolved semantics produce explicit errors.

## Official demo test results

| APK | Default ABI | Extracted / decoded / patched | Output dex files |
|---|---|---|---|
| app-release-protect.apk | ARM64 | 7987 / 7987 / 7987 | 1 |

ARM64 and x86_64 both recovered all 7987 methods. Output dex files passed checksum, method signature, and code_item checks.

## Scope

- Targets existing official dex2c VM implementations; arbitrary modifications to the VM specification are unsupported.
- Does not recover C++ source mode. Additional protection layers must be removed before analyzing the libraries and dex files.
- Does not add invoke-custom / invoke-polymorphic implementations missing from the original VM.
- Rebuilding currently supports original dex versions 035, 037, 038, and 039.
- Semantic probes and structural checks do not replace validation on Android.

## License

This project is licensed under the [MIT License](LICENSE).
