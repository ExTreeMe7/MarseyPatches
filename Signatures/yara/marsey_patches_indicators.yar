/*
  MarseyPatches defensive indicators
  Scope: static triage of SS14/RobustToolbox client patch DLLs.
  Notes: these rules are indicators, not authoritative verdicts. Tune against local false positives.
*/

rule MarseyPatches_Kaban_Client_RAT_Cheat_Composite
{
    meta:
        description = "Kaban.cc-style SS14 client RAT/cheat composite indicators"
        category = "user-risk malware and game abuse"
    strings:
        $s1 = "Kaban.cc" ascii wide
        $s2 = "C2Client" ascii wide
        $s3 = "TelemetrySystem" ascii wide
        $s4 = "DataCollector" ascii wide
        $s5 = "HWIDManager" ascii wide
        $s6 = "AntiVM" ascii wide
        $s7 = "AntiDebug" ascii wide
        $s8 = "AntiDump" ascii wide
        $s9 = "AdvancedAntiDump" ascii wide
        $s10 = "SocketIOClient" ascii wide
        $s11 = "screenshot_ack" ascii wide
    condition:
        uint16(0) == 0x5A4D and 5 of them
}

rule MarseyPatches_FireStation_Bypass_Antidetect
{
    meta:
        description = "FireStation/Melonity verification bypass indicators"
        category = "game abuse / anti-detect"
    strings:
        $s1 = "FireStationBypass" ascii wide
        $s2 = "MelonityVerificationClient" ascii wide
        $s3 = "Harmony" ascii wide
        $s4 = "Subverter" ascii wide
        $s5 = "Sedition" ascii wide
        $s6 = "Ware" ascii wide
    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule MarseyPatches_Admin_Permission_Bypass
{
    meta:
        description = "Client admin/console permission bypass patch indicators"
        category = "game abuse"
    strings:
        $s1 = "CanCommand" ascii wide
        $s2 = "CanScript" ascii wide
        $s3 = "CanAdminMenu" ascii wide
        $s4 = "CanAdminPlace" ascii wide
        $s5 = "GetEntityDescriptionAdmin" ascii wide
        $s6 = "ClientConsoleHost" ascii wide
        $s7 = "CanExecute" ascii wide
    condition:
        uint16(0) == 0x5A4D and 4 of them
}

rule MarseyPatches_AHelp_Admin_Abuse_Commands
{
    meta:
        description = "AHelp/admin abuse command strings"
        category = "game abuse"
    strings:
        $s1 = "ahelpbomber" ascii wide
        $s2 = "SlivAhelp" ascii wide
        $s3 = "SlivBanAll" ascii wide
        $s4 = "SlivKickAll" ascii wide
        $s5 = "SlivKillAll" ascii wide
        $s6 = "BwoinkSystem" ascii wide
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule MarseyPatches_Visual_Bypass_Overlay_FOV
{
    meta:
        description = "Visual limitation bypass patches: flash, overlays, FOV, lights"
        category = "game abuse"
    strings:
        $s1 = "FlashOverlay" ascii wide
        $s2 = "DrawOcclusionDepth" ascii wide
        $s3 = "DrawLightsAndFov" ascii wide
        $s4 = "ApplyFovToBuffer" ascii wide
        $s5 = "DrunkOverlay" ascii wide
        $s6 = "RainbowOverlay" ascii wide
        $s7 = "BlurryVisionOverlay" ascii wide
        $s8 = "TemporaryBlindnessSystem" ascii wide
        $s9 = "EyeDamageSystem" ascii wide
    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule MarseyPatches_NetLogger_Replay_Modify
{
    meta:
        description = "Network packet inspection/replay/modification helper indicators"
        category = "game abuse"
    strings:
        $s1 = "NetLogger" ascii wide
        $s2 = "LogIncomingPacket" ascii wide
        $s3 = "LogOutgoingPacket" ascii wide
        $s4 = "NetMessage" ascii wide
        $s5 = "Replay" ascii wide
        $s6 = "SEND" ascii wide
        $s7 = "RECV" ascii wide
    condition:
        uint16(0) == 0x5A4D and 4 of them
}

rule MarseyPatches_ProcessStart_External_URL_PUP
{
    meta:
        description = "Patch invoking external URL through process launch"
        category = "user-risk PUP"
    strings:
        $s1 = "Process.Start" ascii wide
        $s2 = "https://www.youtube.com/" ascii wide
        $s3 = "OpenNiggas" ascii wide
    condition:
        uint16(0) == 0x5A4D and 2 of them
}
