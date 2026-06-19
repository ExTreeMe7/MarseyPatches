# MarseyPatches

Defensive static-analysis notes and indicators for Marsey/Subverter-style Space Station 14 client patch DLLs.

This repository is intended for server maintainers, anticheat developers, and incident responders who need hashes, static indicators, repository references, and a high-level behavioral map of known client-side patches.

## Scope

This repository tracks defensive material only:

- sanitized static-analysis reports;
- SHA256 hashes for known samples;
- YARA-style static indicators;
- high-level behavior summaries;
- a risk matrix that separates user-device risk from game/server abuse risk.

Raw executable DLL samples and full decompiled source trees are intentionally not tracked in git. This avoids redistributing ready-to-run cheat or malware artifacts while keeping useful defensive signatures available.

## Dataset

Collection date: 2026-06-19.

- Reviewed matrix entries: `81`.
- Baseline entries from the previous set: `59`.
- Newly reviewed entries from `DLLs/NEW`: `22`.
- New raw DLL inventory: `Reports/new_dll_inventory.csv`.
- Public source reference added: `MelvinMod/Sander`.
- Exact duplicate handling: repeated files with the same SHA256 are represented once in the matrix; alternate paths remain available in the inventory CSV.

## Repository Layout

- `README.md` - overview, risk model, repository references, and categorized sample matrix.
- `Reports/source_inventory.csv` - baseline sanitized inventory with sample paths, assembly metadata, sizes, and hashes.
- `Reports/new_dll_inventory.csv` - inventory for the newest local DLL set under `DLLs/NEW`.
- `Reports/dll_copy_map.csv` - relative mapping from original sample name to local DLL workspace layout.
- `Reports/decompiled_copy_map.csv` - relative mapping to decompiled project names from the private analysis workspace.
- `Reports/deep_review_notes.csv` - focused review notes for selected samples.
- `Reports/duplicate_hash_groups.csv` - duplicate analysis grouped by SHA256.
- `Reports/external_repositories.csv` - metadata for related public repositories.
- `Reports/external_forks.csv` - fork comparison notes for related public repositories.
- `Reports/external_commits.csv` - selected recent commits from related public repositories.
- `Reports/root_cs_file_map.csv` - top-level C# file map for decompiled managed projects.
- `Signatures/hashes.sha256` - plain SHA256 list suitable for blocklists or triage scripts.
- `Signatures/patch_matrix.csv` - CSV version of the sample matrix.
- `Signatures/yara/marsey_patches_indicators.yar` - defensive static YARA indicators.

## Risk Model

User Verdict describes risk to the person running the DLL:

- `Safe`: quick static review found no obvious RAT/C2, credential theft, persistence, destructive behavior, unwanted process launch, or similar user-device harm. This is not a clean-room guarantee.
- `Malware`: behavior can harm or surveil the user/device, such as C2/RAT logic, telemetry/data collection, screenshots, HWID tracking, anti-analysis, or similar behavior.
- `Malware/PUP`: potentially unwanted behavior affecting the user's device, such as launching an external URL/process.
- `Unknown`: the sample could not be fully classified from available static analysis.

Game/Server Risk describes abuse risk against SS14 servers and gameplay:

- `Abuse`: ESP/HUD overlays, visual bypasses, admin/console permission bypasses, packet replay/modification, ahelp/chat spam, anti-detect logic, forged UI/network behavior, or automation that can affect server fairness.
- `Dependency`: library used by other samples. A dependency may be harmless by itself while supporting a malicious or abusive sample.
- `None/inert`: no runtime behavior found in this static review, despite the file name or metadata.

## Defensive Usage

Suggested workflow:

1. Use `Signatures/hashes.sha256` for exact sample matching.
2. Use `Reports/source_inventory.csv` and `Reports/new_dll_inventory.csv` to distinguish patch assemblies from dependencies and build artifacts.
3. Use `Signatures/yara/marsey_patches_indicators.yar` for static triage of unknown DLLs.
4. Treat YARA hits as leads, not final verdicts. Confirm with hashes, assembly metadata, loaded type names, runtime behavior, and server-side telemetry.
5. Prioritize high-risk categories: C2/RAT composites, anti-detect/verification bypasses, permission bypasses, packet manipulation, ahelp/admin abuse commands, and screenshot/capture tampering.

Server-side signals worth monitoring at a high level:

- impossible or unauthorized command execution from normal clients;
- repeated ahelp, bwoink, LOOC/OOC, or chat bursts;
- anomalous client messages related to UI actions, purchases, lobby economy, ghost roles, character state, or screenshot/capture responses;
- gameplay patterns consistent with disabled visual limitations, fullbright/no-FOV, unauthorized status information, or combat automation;
- known malicious assembly names, hashes, and static strings during client integrity checks where such checks are permitted.

## External Repository References

Related public repositories were reviewed for defensive context, fork tracking, recursive fork discovery, and commit history. These references are not endorsements and should be treated as untrusted research material.

Collection date: 2026-06-19.

Graph summary:

- repositories recorded: `22`;
- fork edges recorded: `14`;
- recent commit records: `84`;
- recursive depth observed: `2`;
- new source reference: `MelvinMod/Sander`.

### Seed And Root Repositories

| Repository | Defensive relevance | Latest observed commit | Fork/source status |
|---|---|---|---|
| [Androclast/gemini.cc-decomp](https://github.com/Androclast/gemini.cc-decomp) | Gemini/Kaban-family decompiled reference | `84ec05c`: Update README.MD | parent: `-`; forks: `1` |
| [Androclast/SS14.Transmog](https://github.com/Androclast/SS14.Transmog) | SS14 transmog/cosmetic patch reference | `bce52ab`: Non-descriptive update | parent: `-`; forks: `1` |
| [ddepsadd/gemini.cc-decomp](https://github.com/ddepsadd/gemini.cc-decomp) | Gemini/Kaban-family decompiled reference | `84ec05c`: Update README.MD | parent: `Androclast/gemini.cc-decomp`; forks: `0` |
| [ddepsadd/MusyaBlueprints](https://github.com/ddepsadd/MusyaBlueprints) | Musya/FurryLoader blueprint or patch metadata reference | `8975f93`: New blueprint standards | parent: `-`; forks: `0` |
| [ddepsadd/OpenHook](https://github.com/ddepsadd/OpenHook) | Hooking framework/reference repository | `30ea3e5`: Update README.md | parent: `-`; forks: `1` |
| [ddepsadd/photoTroll](https://github.com/ddepsadd/photoTroll) | Screenshot/capture-tampering reference | `b5fb060`: Initial commit | parent: `-`; forks: `0` |
| [DobriyKaban/OpenHook](https://github.com/DobriyKaban/OpenHook) | Hooking framework/reference repository | `4b8baaf`: Update README.md | parent: `ddepsadd/OpenHook`; forks: `0` |
| [DobriyKaban/SS14.Transmog](https://github.com/DobriyKaban/SS14.Transmog) | SS14 transmog/cosmetic patch reference | `bce52ab`: Non-descriptive update | parent: `Androclast/SS14.Transmog`; forks: `0` |
| [ExTreeMe7/FurryAudioReconnect](https://github.com/ExTreeMe7/FurryAudioReconnect) | Benign SS14 OpenAL audio reconnect patch reference | `6abb322`: Initial release | parent: `-`; forks: `0` |
| [MelvinMod/Sander](https://github.com/MelvinMod/Sander) | Source-visible SS14 overlay/aimbot/search mod reference | `23d3556`: Update README.md | parent: `-`; forks: `0`; latest release: `1.6` |
| [noverd/ArabicaCliento](https://github.com/noverd/ArabicaCliento) | Modified SS14 client / patch framework reference | `3a22257`: Merge pull request #9 from noverd/cheatmenu_fix_2025-07-13 | parent: `-`; forks: `11` |

### Recursive Fork Graph

| Fork | Parent | Depth | Compare status | Latest observed commit | Difference summary |
|---|---|---|---|---|---|
| [ddepsadd/gemini.cc-decomp](https://github.com/ddepsadd/gemini.cc-decomp) | `Androclast/gemini.cc-decomp` | `0` | `identical`; ahead `0` / behind `0` | `84ec05c` | No difference from parent at collection time. |
| [DobriyKaban/SS14.Transmog](https://github.com/DobriyKaban/SS14.Transmog) | `Androclast/SS14.Transmog` | `0` | `identical`; ahead `0` / behind `0` | `bce52ab` | No difference from parent at collection time. |
| [DobriyKaban/OpenHook](https://github.com/DobriyKaban/OpenHook) | `ddepsadd/OpenHook` | `0` | `behind`; ahead `0` / behind `3` | `4b8baaf` | Old snapshot behind parent by 3 commits; no unique ahead commits. |
| [AZERBAIJAN-TECH/AzerbicaCliento](https://github.com/AZERBAIJAN-TECH/AzerbicaCliento) | `noverd/ArabicaCliento` | `1` | `ahead`; ahead `7` / behind `0` | `7104efc` | Forward fork ahead by 7 commits. Changed areas: `.github`, `ArabicaCliento`, solution/build files, README, and vendored `space-station-14`. |
| [cheltyi/ArabicaCliento](https://github.com/cheltyi/ArabicaCliento) | `noverd/ArabicaCliento` | `1` | `behind`; ahead `0` / behind `16` | `96c39ad` | Old snapshot behind parent by 16 commits; no unique ahead commits. |
| [d0r11s1m0/ArabicaCliento](https://github.com/d0r11s1m0/ArabicaCliento) | `noverd/ArabicaCliento` | `1` | `identical`; ahead `0` / behind `0` | `3a22257` | No difference from parent at collection time. |
| [hircani200/ArabicaCliento](https://github.com/hircani200/ArabicaCliento) | `noverd/ArabicaCliento` | `1` | `behind`; ahead `0` / behind `16` | `96c39ad` | Old snapshot behind parent by 16 commits; no unique ahead commits. |
| [kakih-user/ArabicaCliento](https://github.com/kakih-user/ArabicaCliento) | `noverd/ArabicaCliento` | `1` | `identical`; ahead `0` / behind `0` | `3a22257` | No difference from parent at collection time. |
| [LetBoss/s](https://github.com/LetBoss/s) | `noverd/ArabicaCliento` | `1` | `identical`; ahead `0` / behind `0` | `3a22257` | No difference from parent at collection time. |
| [lexaSvarshik/ArabicaCliento](https://github.com/lexaSvarshik/ArabicaCliento) | `noverd/ArabicaCliento` | `1` | `behind`; ahead `0` / behind `20` | `8b1969b` | Old snapshot behind parent by 20 commits; no unique ahead commits. |
| [shepardzs/ArabicaCliento](https://github.com/shepardzs/ArabicaCliento) | `noverd/ArabicaCliento` | `1` | `ahead`; ahead `2` / behind `0` | `5d19412` | Forward fork ahead by 2 commits. Changed areas: `.github` and `ArabicaCliento`. |
| [TerrariumCat/ArabicaCliento](https://github.com/TerrariumCat/ArabicaCliento) | `noverd/ArabicaCliento` | `1` | `identical`; ahead `0` / behind `0` | `3a22257` | No difference from parent at collection time. |
| [xsainteer/ArabicaCliento-xsainteer](https://github.com/xsainteer/ArabicaCliento-xsainteer) | `noverd/ArabicaCliento` | `1` | `identical`; ahead `0` / behind `0` | `3a22257` | No difference from parent at collection time. |
| [voko421/AzerbicaCliento](https://github.com/voko421/AzerbicaCliento) | `AZERBAIJAN-TECH/AzerbicaCliento` | `2` | `identical`; ahead `0` / behind `0` | `7104efc` | No difference from parent at collection time. |

Detailed repository, fork, and commit data is also available in:

- `Reports/external_repositories.csv`
- `Reports/external_forks.csv`
- `Reports/external_commits.csv`

## Categorized Sample Matrix

`Hash8` is the first eight characters of SHA256. Use `Signatures/patch_matrix.csv` and `Signatures/hashes.sha256` for full hashes.

### User-Device Malware, PUP, And High-Risk Stealth

| Item | Hash8 | User Verdict | Game/Server Risk | Decompiled/source reference | Defensive summary |
|---|---:|---|---|---|---|
| `Mods/Kaban.cc.dll` | `3E6500CD` | Malware | Abuse + RAT/C2/spyware | `Kaban.cc__Kaban.cc__3E6500CD` | Full RAT/cheat suite: WebView2/ImGui UI, ESP, aimbot, automation, anti-debug, anti-dump, anti-VM, assembly/type/component hiding, HWID/license logic, telemetry, screenshot capture, data collection, and Socket.IO C2 command handling. |
| `CerbFix/CerberusWareV3.dll` | `62D9C8E3` | Malware | Abuse + anti-detect + ESP/aimbot suite | `CerberusWareV3__CerberusWareV3__62D9C8E3` | Large cheat suite with ImGui UI, anticheat system/event/log blockers, assembly/type/component hiding, fullbright/FOV bypass, storage and implant viewers, antag detection, aim helpers, spam/ahelp automation, screenshot overlay hiding, external translation HTTP calls, and AppData config/state files. |
| `AntiCheatBypass.dll` | `C1457D01` | Safe | Abuse: anti-cheat/anti-detect bypass | `AntiCheatBypass__ClassLibrary1__C1457D01` | Obfuscated Cerberus anti-AC module. Static review found Harmony patches for `ReflectionManager.FindAllTypes`, `EntitySystemManager.GetEntitySystemTypes`, assembly enumeration, IoC-related filtering, and `Type.GetType`, hiding suspicious names/types from local checks. |
| `SunriseObhod14.dll` | `1299BDD4` | Safe | Abuse: role verification / anti-detect bypass | `SunriseObhod14__SunriseObhod14__1299BDD4` | Heavily obfuscated sample with `SuppressIldasm`, encrypted string/resource logic, Harmony target methods against `RoleVerificationClient`, and metadata-hiding style. No obvious user-device C2 was found in this quick static pass, but the anti-detect role-verification bypass risk is high. |
| `FireStationBypass.dll` | `36438BFC` | Safe | Abuse: anti-cheat/anti-detect bypass | `FireStationBypass__FireStationBypass__36438BFC` | Patches `MelonityVerificationClient`, forges clean verification responses, and hides `Harmony`, `Subverter`, `Marsey`, `Sedition`, and `Ware` type lookups. |
| `photoTroll.dll` | `BB32043E` | Safe | Abuse: screenshot/capture tampering | `photoTroll__photoTroll__BB32043E` | Patches `CaptureSystem.RequestCaptureScreen`; when `Marsey/Mods/photoTroll/image.png` exists, it sends a fake `CaptureScreenResponseEvent` with that image and suppresses the original capture request. |
| `SuperGovnoWare.dll` | `435329C4` | Malware/PUP | PUP: opens external URL | `SuperGovnoWare__SuperGovnoWare__435329C4` | Invokes an external URL through process launch behavior. Even if intended as a prank, it is unwanted process/browser launch behavior. |
| `fayliki dlya bistrogo vzyatiya prof gosta.dll` | `20F35AD8` | Unknown | Unknown native/non-managed | none | 440-byte non-managed file. `AssemblyName.GetAssemblyName` reports unknown file format; not classifiable by managed .NET review. |

### Admin, Console, Permission, And Information Bypass

| Item | Hash8 | User Verdict | Game/Server Risk | Decompiled/source reference | Defensive summary |
|---|---:|---|---|---|---|
| `AdminPatch.dll` | `5956B7AD` | Safe | Abuse: admin permission bypass | `AdminPatch__AdminPatch__5956B7AD` | Forces local admin checks such as `CanCommand`, `CanScript`, `CanAdminMenu`, `CanAdminPlace`, and `IsActive`; also replaces entity descriptions with admin descriptions. |
| `patches/AdminPatch.dll` | `6E40E079` | Safe | Abuse: admin and console permission bypass | `AdminPatch__AdminPatch__6E40E079` | Newer admin patch build. Adds/keeps forced `ClientAdminManager` permissions, console `CanExecute`, `CanSay`, and admin entity description replacement. |
| `CommandPermissionPatch.dll` | `FA4C8C41` | Safe | Abuse: command permission bypass | `CommandPermissionPatch__CommandPermissionPatch__FA4C8C41` | Harmony-postfixes `Robust.Client.Console.ClientConsoleHost.CanExecute` and forces command execution permission to true. |
| `Zazi4kaMod_1.dll` | `91BCD5C2` | Safe | Abuse: admin description leak | `Zazi4kaMod_1__Zazi4kaMod__91BCD5C2` | Patches entity menu description lookup and substitutes `GetEntityDescriptionAdmin`, exposing admin-only entity descriptions to the client. |
| `fullhud.dll` | `77AFC8A6` | Safe | Abuse: HUD/status info bypass | `fullhud__superhudoverlay__77AFC8A6` | Patches HUD/status icon paths to expose extra job/status information normally unavailable to normal players. |
| `HudOverlaysPatch.dll` | `389A17AE` | Safe | Abuse: HUD/status info bypass | `HudOverlaysPatch__HudOverlaysPatch__389A17AE` | Similar to `fullhud`; adds or exposes extra overlay components/icons. |
| `Chemical_Scan_Patch.dll` | `C5DE0A51` | Safe | Abuse: chemical information bypass | `Chemical_Scan_Patch__Chemical_Scan_Patch__C5DE0A51` | Adds `SolutionScannerComponent` to the local player on attach, enabling chemical scan-style information without normal item/role requirements. |
| `Sander.dll` | `B6D170E6` | Safe | Abuse: ESP/search/implant/role overlays | `Sander__Sander__B6D170E6`; source: `MelvinMod/Sander` | Source-visible overlay/search mod. Adds item search, implant display, coordinate markers, syndicate/pirate labels, sound subtitles, footsteps, fullbright/shadow/FOV toggles, and a target-selection aimbot overlay. |
| `BBT.Ware.dll` | `6D3B2690` | Safe | Abuse: HUD/ESP/admin bypass/visual bypass | `BBT.Ware__BBT.Ware__6D3B2690` | Cheat/HUD/ESP framework with local admin bypass, entity descriptions, health/job/criminal/mindshield/syndicate icons, name overlay, no-FOV/no-overlay, smoke/foam/fov controls, and menu UI. No direct user-device malware indicators were found in this SHA. |
| `Based.dll` | `70B16B98` | Safe | Abuse: cheat framework/admin bypass/ESP | `Based__Based__70B16B98` | Cheat framework with local admin checks bypassed, assembly hiding through reflection manager paths, fullbright/subfloor/job overlay, visual bypasses, UI, and aimbot via predictive attack events. |
| `FreeOverlay.dll` | `15CB78F7` | Safe | Abuse: ESP/overlay | `FreeOverlay__ClassLibrary1__15CB78F7` | Adds an overlay drawing entity names/statuses and local combat indicators, providing ESP-like information. |
| `GhostPatch.dll` | `CA3CCA8F` | Safe | Abuse: ghost visibility bypass | `GhostPatch__GhostPatch__CA3CCA8F` | Patches `GhostSystem` to force ghost visibility and keep ghost sprite/layers visible after startup, attach, detach, and state changes. |

### Visual Limitation Bypass

| Item | Hash8 | User Verdict | Game/Server Risk | Decompiled/source reference | Defensive summary |
|---|---:|---|---|---|---|
| `DODPatch.dll` | `465FF6E5` | Safe | Abuse: visual bypass | `DODPatch__DODPatch__465FF6E5` | Blocks `Clyde.DrawOcclusionDepth`, disabling depth/occlusion rendering and related visual limitations. |
| `DODPatch.dll` | `359EBE88` | Safe | Abuse: visual bypass | `DODPatch__DODPatch__359EBE88` | New build of the occlusion-depth bypass using reflected `Robust.Client.Graphics.Clyde.Clyde` lookup. |
| `FlashPatch.dll` | `458DA839` | Safe | Abuse: visual bypass | `FlashPatch__FlashPatch__458DA839` | Prefix skips `Content.Client.Flash.FlashOverlay.Draw`, disabling flash effects. |
| `FlashPatch.dll` | `A3B1D3F8` | Safe | Abuse: visual bypass | `FlashPatch__FlashPatch__A3B1D3F8` | New reflected build of the flash overlay disabler. |
| `FoamControll.dll` | `4A4FBE36` | Safe | Abuse: visual bypass | `FoamControll__FoamControll__4A4FBE36` | Adds command/CVar control for foam transparency, reducing a normal visual obstacle. |
| `LightDisabler.dll` | `091466FF` | Safe | Abuse: fullbright/no-FOV | `LightDisabler__LightDisabler__091466FF` | Blocks `Clyde.ApplyFovToBuffer` and `Clyde.DrawLightsAndFov`, producing fullbright/no-FOV behavior. |
| `NoOverlay.dll` | `EF47584C` | Safe | Abuse: visual bypass | `NoOverlay__NoOverlay__EF47584C` | Blocks flash, blind, blurry, temporary blindness, and eye damage paths. |
| `OverlaysPatch_1.dll` | `2D905D35` | Safe | Abuse: visual bypass | `OverlaysPatch_1__OverlaysPatch__2D905D35` | Simplified overlay bypass for drunk, rainbow, blind, and blurry overlays. |
| `OverlaysPatch.dll` | `A8C1E6C1` | Safe | Abuse: visual bypass | `OverlaysPatch__OverlaysPatch__A8C1E6C1` | More complete overlay bypass for drunk, rainbow, blind, and blurry overlays. |
| `patches/OverlaysPatch.dll` | `EF514ED6` | Safe | Abuse: visual bypass | `OverlaysPatch__OverlaysPatch__EF514ED6` | New v2 build that postfixes overlay pre-draw checks for drunk, rainbow, blurry, and blind overlays. |
| `SmokePatch.dll` | `48ECB1F9` | Safe | Abuse: visual bypass | `SmokePatch__SmokePatch__48ECB1F9` | Prefix skips smoke visualizer rendering. Metadata label is misleading and still says flash overlay disabler. |
| `Robusto_1.dll` / `Robusto.dll` | `5AAF4029` | Safe | Abuse: visual bypass | `Robusto_1__Robusto__5AAF4029` | Disables FOV, light/shadows, stealth shader, drunk/rainbow/blind/blurry/flash overlays. |
| `UpNoOverlay.dll` | `37FDC0BA` | Safe | Abuse: visual bypass | `UpNoOverlay__UpNoOverlay__37FDC0BA` | Expanded visual bypass: damage, drunk, rainbow, blind, blurry, flash, occlusion depth, and smoke visuals. |
| `patches/UpNoOverlay.dll` | `50B1E84D` | Safe | Abuse: visual bypass | `UpNoOverlay__UpNoOverlay__50B1E84D` | New build disabling damage, drunk, rainbow, blurry, blind, flash, and Clyde occlusion-depth rendering. |
| `GYK3h5m.dll` | `498502F3` | Safe | Abuse: no-FOV/no-overlay/no-flash | `GYK3h5m__NewRobustFix__498502F3` | Obscure file name; assembly is `NewRobustFix`. Targets drunk, rainbow, blurry, blind, flash, and Clyde depth methods. |

### Spam, Chat, AHelp, And Action Abuse

| Item | Hash8 | User Verdict | Game/Server Risk | Decompiled/source reference | Defensive summary |
|---|---:|---|---|---|---|
| `AdminExploit.dll` | `8748E9EE` | Safe | Abuse: chat spam | `AdminExploit__TextHelper__8748E9EE` | Registers `TakeAdmin`; visible behavior is fast infinite `say` spam with an ASCII banner and config file creation, not actual admin privilege acquisition. |
| `AdminSliver.dll` | `F8831DE1` | Safe | Abuse: mass admin actions/ahelp spam | `AdminSliver__AdminSliver__F8831DE1` | Registers commands such as `SlivBanAll`, `SlivKickAll`, `SlivKillAll`, `SlivAhelp`, and `SlivPlayerList`; uses admin systems, console commands, and ahelp/Bwoink paths for mass disruption. |
| `AHelpBomber.dll` | `9940328D` | Safe | Abuse: ahelp spam | `AHelpBomber__AhelpBomber__9940328D` | `ahelpbomber` sends ahelp messages in a tight loop with roughly 10 ms delay through `BwoinkSystem.Send`. |
| `HRP_Spam_Patch.dll` | `B2F73069` | Safe | Abuse: roleplay action spam | `HRP_Spam_Patch__HRP_Spam_Patch__B2F73069` | Adds `starthrpspam` and `stophrpspam`; repeatedly executes `me` commands for heartbeat, blinking, and breathing loops. |
| `Smart_Spam_Patch.dll` | `61EAC9C1` | Safe | Abuse: chat spam | `Smart_Spam_Patch__SimpleCommand__61EAC9C1` | Adds `startspam` and `editspam`; configurable repeated `say` spam with message count and delay. |
| `SpamMod.dll` | `3544E2EC` | Safe | Abuse: spam/anti-spam evasion | `SpamMod__SpamPatch__3544E2EC` | Adds `spamprotect`; reads `Marsey/Config/SpamText.txt` and sends repeated radio-style messages with randomized suffixes intended to bypass anti-spam filters. |
| `jerk.dll` | `916B0BD4` | Safe | Abuse: action spam/crash-like behavior | `jerk__jerk__916B0BD4` | Contains `JerkCrash`, which repeatedly invokes hand UI clicks while hands are free; may be used for spam, desync, or crash-like behavior. |

### Network, UI, Economy, Role, And Gameplay Exploit Helpers

| Item | Hash8 | User Verdict | Game/Server Risk | Decompiled/source reference | Defensive summary |
|---|---:|---|---|---|---|
| `CMExploit.dll` | `01149641` | Safe | Abuse: forged UI/network action | `CMExploit__CMExploit__01149641` | `cmexploit` forges a xeno evolution UI message with a selected prototype id through reflected `SharedUserInterfaceSystem.SendUiMessage`. |
| `ForceListing_1.dll` / `ForceListing.dll` | `AEBE1B62` | Safe | Abuse: purchase restriction bypass | `ForceListing_1__ForceListing__AEBE1B62` | Prefixes `StoreListingControl` constructor and forces `canBuy = true`, bypassing UI purchase restrictions. |
| `FrontierExploit.dll` | `0BE2E889` | Safe | Abuse: forged economy update | `FrontierExploit__FrontierExploit__0BE2E889` | Command changes a selected lobby character `BankBalance` and sends `MsgUpdateCharacter` to the server. |
| `NetLogger.dll` | `3ED27194` | Safe | Abuse: packet inspect/replay/modify | `NetLogger__NetLogger__3ED27194` | Patches network logging, shows SEND/RECV packets, stores recent messages, and provides UI for inspection, replay, and modified packet sending. |
| `RRTBypass.dll` | `FB48568C` | Safe | Abuse: ghost role request restriction bypass | `RRTBypass__RRTBypass__FB48568C` | Postfixes `GhostRoleRulesWindow.FrameUpdate` and forces the request button `Disabled` property to false. |
| `GodMode Exploit.dll` | `258F3C79` | Safe | None/inert metadata | `GodMode_Exploit__GodMode_Exploit__258F3C79` | Despite the file name, static review found only `SubverterPatch` metadata and assembly info. No command, patch target, system, or runtime logic was found. |
| `somth.dll` | `167A5201` | Safe | Abuse: combat stat cheat | `somth__somth__167A5201` | Harmony-postfixes `MeleeWeaponComponent` and forces `AttackRate = 99f`. |
| `SukaDaKakogoHuya.dll` | `00612F05` | Safe | Abuse: character/species restriction bypass | `SukaDaKakogoHuya__SukaDaKakogoHuya__00612F05` | Patches `HumanoidProfileEditor`, expands/changes species selection, and invokes `SetSpecies`/picker updates. |
| `InstantPickup.dll` | `3668155D` | Safe | Abuse: input/action automation | `InstantPickup__InstantPickup__3668155D` | Patches item hand interaction to pick up directly, redirects pickup verb execution, and intercepts smart backpack/belt hotkeys to pull the last stored item from storage through predictive storage UI events. |

### Modding Frameworks, Runtime Script Bridges, And Hooking UI

| Item | Hash8 | User Verdict | Game/Server Risk | Decompiled/source reference | Defensive summary |
|---|---:|---|---|---|---|
| `Lua14.dll` | `6360ECF1` | Safe | Dual-use: runtime patch scripting | `Lua14__Lua14__6360ECF1` | Loads zip-based Lua mods from a `LuaMods` folder, exposes reflection and Harmony patch APIs to Lua, and registers `lua14.loadstring`. Powerful modding surface with high abuse potential if untrusted scripts are present. |
| `OpenHook.dll` | `6F610E6C` | Safe | Dual-use: ImGui/hooking framework | `OpenHook__OpenWare__6F610E6C` | Early/debug OpenWare build. Hooks Robust rendering/input, creates an ImGui overlay, and provides menu/input bridge infrastructure. Mainly a loader/UI framework by itself. |
| `OpenWare.dll` | `AFAF78C7` | Safe | Dual-use: ImGui/hooking framework | `OpenWare__OpenWare__AFAF78C7` | Release OpenWare build. Hooks `Clyde.GLContextWindow.SwapAllBuffers`, bridges keyboard/mouse/SDL text input into ImGui, blocks game binds while overlay captures input, and shows a debug overlay with placeholder actions. |
| `RotatePath.dll` | `4395DA06` | Safe | None/inert utility | `RotatePath__RotatePath__4395DA06` | `spin on/off` changes a static flag, but no code was found that applies rotation. Appears incomplete or inert. |
| `Rethemer.dll` | `7E41D3FA` | Safe | Cosmetic | `Rethemer__Rethemer__7E41D3FA` | Cosmetic style transpiler for `StyleNano` and `MenuButton`; changes stylesheet/menu theme to a Marsey-style variant. |
| `AhelpNot.dll` | `3ABB56C2` | Safe | None/inert | `AhelpNot__AhelpNot__3ABB56C2` | Inert/incomplete Subverter metadata sample. No command, `PatchAll`, AHelp/Bwoink hook, popup/sound suppression, or runtime logic was found in this SHA. |

### Dependencies And Build Artifacts

| Item | Hash8 | User Verdict | Game/Server Risk | Decompiled/source reference | Defensive summary |
|---|---:|---|---|---|---|
| `Lidgren.Network.dll` | `25A1CBC6` | Safe | Dependency | `Lidgren.Network__Lidgren.Network__25A1CBC6` | Third-party Lidgren networking library. No patch behavior by itself. |
| `Mods/SpaceWizards.Lidgren.Network.dll` | `3A9D41BB` | Safe | Dependency | `SpaceWizards.Lidgren.Network__SpaceWizards.Lidgren.Network__3A9D41BB` | Space Wizards fork/dependency for Lidgren networking. |
| `Serilog.dll` | `BA73B4BF` | Safe | Dependency | `Serilog__Serilog__BA73B4BF` | Standard logging dependency. |
| `Mods/Newtonsoft.Json.dll` | `A28C251D` | Safe | Dependency | `Newtonsoft.Json__Newtonsoft.Json__A28C251D` | JSON dependency. |
| `Mods/Hexa.NET.ImGui.Backends.dll` | `A8AC0B89` | Safe | Dependency | `Hexa.NET.ImGui.Backends__Hexa.NET.ImGui.Backends__A8AC0B89` | ImGui backend dependency. |
| `Mods/Hexa.NET.ImGui.dll` | `4E73425C` | Safe | Dependency | `Hexa.NET.ImGui__Hexa.NET.ImGui__4E73425C` | ImGui bindings dependency. |
| `Mods/HexaGen.Runtime.dll` | `DEDAFE0C` | Safe | Dependency | `HexaGen.Runtime__HexaGen.Runtime__DEDAFE0C` | Hexa-generated runtime dependency. |
| `Mods/KeraLua.dll` | `A0EC77CE` | Safe | Dependency | `KeraLua__KeraLua__A0EC77CE` | Lua runtime binding dependency. |
| `Mods/NLua.dll` | `29AF6AF4` | Safe | Dependency | `NLua__NLua__29AF6AF4` | Lua integration dependency. |
| `Mods/Microsoft.Web.WebView2.Core.dll` | `2B999D17` | Safe | Dependency | `Microsoft.Web.WebView2.Core__Microsoft.Web.WebView2.Core__2B999D17` | WebView2 dependency used by `Kaban.cc` for UI. |
| `Mods/Microsoft.Web.WebView2.Wpf.dll` | `B6A200F3` | Safe | Dependency | `Microsoft.Web.WebView2.Wpf__Microsoft.Web.WebView2.Wpf__B6A200F3` | WebView2 WPF dependency. |
| `Mods/MinHook.NET.dll` | `75DCAF80` | Safe | Dual-use dependency | `MinHook.NET__MinHook.NET__75DCAF80` | Hooking dependency. Harmless as a library, but dual-use and present beside high-risk samples. |
| `Mods/SocketIOClient.dll` | `8D37BA5C` | Safe | Dependency used by malware | `SocketIOClient__SocketIOClient__8D37BA5C` | Socket.IO dependency used by `Kaban.cc` C2 logic. |
| `Mods/System.Drawing.Common.dll` | `96502314` | Safe | Dependency used by screenshot code | `System.Drawing.Common__System.Drawing.Common__96502314` | .NET drawing dependency; associated with screenshot/image code in `Kaban.cc`. |
| `Mods/PresentationCore.dll` | `83B1D7D6` | Safe | Dependency | `PresentationCore__PresentationCore__83B1D7D6` | WPF dependency. |
| `Mods/PresentationFramework.dll` | `40FEE697` | Safe | Dependency | `PresentationFramework__PresentationFramework__40FEE697` | WPF dependency. |
| `Mods/System.IO.Packaging.dll` | `08E66248` | Safe | Dependency | `System.IO.Packaging__System.IO.Packaging__08E66248` | .NET packaging dependency. |
| `Mods/System.Windows.Forms.dll` | `2292F948` | Safe | Dependency | `System.Windows.Forms__System.Windows.Forms__2292F948` | Windows Forms dependency. |
| `Mods/System.Xaml.dll` | `29E6A408` | Safe | Dependency | `System.Xaml__System.Xaml__29E6A408` | XAML dependency. |
| `Mods/UIAutomationProvider.dll` | `12920B58` | Safe | Dependency | `UIAutomationProvider__UIAutomationProvider__12920B58` | UIAutomation dependency. |
| `Mods/UIAutomationTypes.dll` | `FDC014EC` | Safe | Dependency | `UIAutomationTypes__UIAutomationTypes__FDC014EC` | UIAutomation dependency. |
| `Mods/WindowsBase.dll` | `181153DF` | Safe | Dependency | `WindowsBase__WindowsBase__181153DF` | WPF/WindowsBase dependency. |
| `Mods/WinRT.Runtime.dll` | `2238FECF` | Safe | Dependency | `WinRT.Runtime__WinRT.Runtime__2238FECF` | WinRT runtime dependency. |
| `Mods/WebView2Loader.dll` | `8427B1FC` | Safe | Native dependency | none | Native WebView2 loader. Not managed .NET; tracked as dependency. |

## Notable High-Risk Groups

### User-Device Malware

`Kaban.cc.dll` remains the highest-confidence user-device malware sample in the baseline set because it combines C2, telemetry, screenshot/data collection, HWID tracking, anti-analysis logic, and extensive gameplay automation.

`CerberusWareV3.dll` is now the largest newly reviewed high-risk sample. It does not show the same clear Socket.IO RAT pattern as `Kaban.cc` in this quick pass, but it does contain aggressive anti-detect, screenshot/capture-related hiding, AppData config persistence, external HTTP translation calls, ESP/aimbot overlays, and spam automation. It should be treated as a high-risk cheat suite.

### Anti-Detect And Verification Bypass

`AntiCheatBypass.dll`, `SunriseObhod14.dll`, and `FireStationBypass.dll` are the most important anti-detect samples. They target local verification, type discovery, entity system discovery, assembly enumeration, role verification, and suspicious type/name filtering.

### Server/Game Abuse

Common abuse families in the reviewed set:

- visual bypasses: flash, blindness, overlays, FOV, lighting, smoke/foam, and occlusion changes;
- HUD/ESP overlays: hidden role/status/job/entity/storage/implant information exposure;
- permission bypasses: local admin and console permission checks forced open;
- packet tools: packet inspection, replay, or modification helpers;
- spam/destructive admin helpers: chat, ahelp, LOOC/OOC, `me`, and mass action command strings;
- anti-detect logic: verification response tampering, assembly/type/component hiding, and screenshot/capture tampering;
- modding frameworks: ImGui, Lua, Harmony, and reflection bridges that are not always malicious by themselves but materially lower the cost of abusive patches.

## Important Limitations

Static analysis can miss packed, obfuscated, staged, or environment-dependent behavior. Absence of a hit does not prove a file is safe.

File names are not stable indicators. Different builds may use the same DLL name while having different behavior, and several samples in `DLLs/NEW` are renamed or rebuilt versions of older patches. Prefer SHA256, assembly metadata, static strings, and behavior notes when comparing reports.

Dependency DLLs should not be blocked only by name without context. They may be legitimate libraries but still useful as correlation signals when found beside known abusive patch assemblies.

## Publication Notes

The git repository intentionally excludes `DLLs/` and `Decompiled/`. Keep raw samples in a private malware-analysis workspace, preferably isolated from normal user environments. Publish hashes, indicators, and high-level behavior notes when sharing with other defenders.
