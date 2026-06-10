# Signatures

Defensive indicators derived from static analysis of known Marsey/Subverter-style SS14 client patch DLLs.

## Files

- `hashes.sha256` - exact SHA256 matches for known samples.
- `patch_matrix.csv` - per-sample summary with user-device risk and game/server risk.
- `yara/marsey_patches_indicators.yar` - static YARA indicators for triage.

## Recommended Use

1. Match hashes first. A hash hit is the strongest indicator for a known sample.
2. Use YARA hits as leads for manual review, not as automatic ban evidence by themselves.
3. Separate dependency hits from patch hits. Libraries such as JSON, WebView2, ImGui, Lidgren, or Socket.IO may be harmless by themselves.
4. Combine static indicators with server-side behavior: command abuse, abnormal client messages, scripted chat/ahelp bursts, or impossible visibility/status knowledge.

## Caution

These signatures are static indicators. They may miss modified builds, packed assemblies, or renamed/obfuscated forks, and they may produce false positives on legitimate dependencies.
