/*
 * YARA rules for killa payload risk-scanning (defensive / informational).
 *
 * Notes:
 * - These rules are intended to help operators understand detection exposure.
 * - They are not a bypass mechanism.
 * - Rule set refreshed for the killa rebrand and Slack/Dropbox-capable transport stack.
 */

rule Killa_Go_Binary_Baseline
{
    meta:
        description = "Go-compiled binary baseline"
        severity = "info"
        category = "language"
    strings:
        $go_buildid = "Go build ID:" ascii
        $go_runtime = "runtime.goexit" ascii
        $go_pclntab = ".gopclntab" ascii
    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F or uint32(0) == 0xFEEDFACF or uint32(0) == 0xFEEDFACE)
        and 1 of ($go_*)
}

rule Killa_Runtime_Identity_Indicators
{
    meta:
        description = "killa-specific identity and transport markers"
        severity = "high"
        category = "identity"
    strings:
        $killa_name = "PayloadType: \"killa\"" ascii
        $killa_c2_http = "C2Profile: \"http\"" ascii
        $killa_c2_tcp = "C2Profile: \"tcp\"" ascii
        $killa_c2_slack = "C2Profile: \"slack\"" ascii
        $killa_c2_dropbox = "C2Profile: \"dropbox\"" ascii
    condition:
        $killa_name and 1 of ($killa_c2_*)
}

rule Killa_Mythic_Container_Indicators
{
    meta:
        description = "Mythic container integration strings"
        severity = "high"
        category = "c2"
    strings:
        $mythic_a = "MythicMeta" ascii
        $mythic_b = "mythicrpc" ascii
        $mythic_c = "MythicServicePayload" ascii
        $mythic_d = "MythicServiceC2" ascii
    condition:
        2 of them
}

rule Killa_Slack_Dropbox_Transport_Indicators
{
    meta:
        description = "Cloud transport stack indicators for Slack/Dropbox-enabled builds"
        severity = "medium"
        category = "transport"
    strings:
        $slack_pkg = "github.com/slack-go/slack" ascii
        $slack_c2 = "slack_bot_token" ascii
        $dropbox_api = "https://api.dropboxapi.com/2" ascii
        $dropbox_content = "https://content.dropboxapi.com/2" ascii
        $dropbox_c2 = "dropbox_token" ascii
    condition:
        ($slack_pkg and $slack_c2) or (($dropbox_api or $dropbox_content) and $dropbox_c2)
}

rule Killa_Windows_Injection_Surface
{
    meta:
        description = "Windows process injection API surface"
        severity = "high"
        category = "injection"
    strings:
        $api1 = "VirtualAllocEx" ascii wide
        $api2 = "WriteProcessMemory" ascii wide
        $api3 = "CreateRemoteThread" ascii wide
        $api4 = "NtMapViewOfSection" ascii wide
        $api5 = "QueueUserAPC" ascii wide
        $api6 = "SetThreadContext" ascii wide
    condition:
        2 of them
}

rule Killa_Credential_Access_Surface
{
    meta:
        description = "Credential-access API surface"
        severity = "medium"
        category = "credential"
    strings:
        $cred1 = "LsaEnumerateLogonSessions" ascii wide
        $cred2 = "CredEnumerateW" ascii wide
        $cred3 = "CryptUnprotectData" ascii wide
        $cred4 = "SamConnect" ascii wide
        $cred5 = "WDigest" ascii wide nocase
    condition:
        2 of them
}

rule Killa_Defense_Evasion_Surface
{
    meta:
        description = "Defense-evasion API surface"
        severity = "high"
        category = "evasion"
    strings:
        $ev1 = "EtwEventWrite" ascii wide
        $ev2 = "AmsiScanBuffer" ascii wide
        $ev3 = "NtProtectVirtualMemory" ascii wide
        $ev4 = "NtQueryInformationProcess" ascii wide
    condition:
        2 of them
}

rule Killa_Plaintext_Config_Exposure
{
    meta:
        description = "Potential plaintext C2/config exposure in built payload"
        severity = "high"
        category = "opsec"
    strings:
        $cfg1 = "callback_host" ascii
        $cfg2 = "callback_port" ascii
        $cfg3 = "slack_channel_id" ascii
        $cfg4 = "dropbox_task_folder" ascii
        $cfg5 = "Mozilla/5.0" ascii
    condition:
        3 of them
}
