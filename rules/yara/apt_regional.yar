/*
 * AISS YARA Rules — APT & Regional Threat Intelligence
 *
 * Covers threats prioritised by:
 *  - Singapore CSA Cyber Threat Landscape 2023-2024
 *  - CISA/NSA joint advisories (PRC/DPRK/RU threat actors)
 *  - MAS Cybersecurity Advisory 2023
 *  - Japan METI/NPA threat bulletins
 *  - Korea KISA threat catalogue
 *
 * Compliance: Singapore IM8 v5.0, MAS TRM 2021, CSA Cybersecurity Act 2018
 */

// ── ProxyLogon — Microsoft Exchange RCE (CVE-2021-26855) ─────────────────────
rule APT_ProxyLogon_CVE_2021_26855 {
    meta:
        description = "Detects ProxyLogon exploitation targeting Microsoft Exchange"
        cve         = "CVE-2021-26855"
        severity    = "CRITICAL"
        cvss        = "9.8"
        threat_actor = "HAFNIUM (PRC) — actively exploited in SE Asia"
        reference   = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
    strings:
        $cookie1   = "X-BEResource"                    ascii nocase
        $cookie2   = "X-AnonResource"                  ascii nocase
        $autodiscov = "/autodiscover/autodiscover.xml"  ascii nocase
        $ews1      = "/ews/exchange.asmx"               ascii nocase
        $ssrf_host = "~/appconfig"                      ascii nocase
    condition:
        ($cookie1 or $cookie2) or ($autodiscov and $ews1)
}

// ── PrintNightmare — Windows Print Spooler RCE (CVE-2021-34527) ──────────────
rule APT_PrintNightmare_CVE_2021_34527 {
    meta:
        description = "Detects PrintNightmare exploitation payload patterns"
        cve         = "CVE-2021-34527"
        severity    = "CRITICAL"
        cvss        = "8.8"
        reference   = "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527"
    strings:
        $spooler1  = "Windows Print Spooler"   ascii nocase
        $spooler2  = "spoolsv.exe"             ascii nocase
        $unc_path  = "\\\\%*\\pipe\\"          ascii
        $dll_inject = "AddPrinterDriverEx"     ascii
    condition:
        ($spooler1 or $spooler2) and ($unc_path or $dll_inject)
}

// ── ZeroLogon — Netlogon Privilege Escalation (CVE-2020-1472) ────────────────
rule APT_ZeroLogon_CVE_2020_1472 {
    meta:
        description = "Detects ZeroLogon Netlogon protocol exploitation"
        cve         = "CVE-2020-1472"
        severity    = "CRITICAL"
        cvss        = "10.0"
        threat_actor = "Multiple APT groups"
    strings:
        $netlogon1 = "NetrServerAuthenticate"    ascii
        $netlogon2 = "NetrServerPasswordSet"     ascii
        $zeroes    = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        ($netlogon1 or $netlogon2) and #zeroes > 5
}

// ── F5 BIG-IP iControl RCE (CVE-2022-1388) ───────────────────────────────────
rule APT_F5_BIG_IP_CVE_2022_1388 {
    meta:
        description = "Detects F5 BIG-IP iControl REST authentication bypass"
        cve         = "CVE-2022-1388"
        severity    = "CRITICAL"
        cvss        = "9.8"
        affected    = "F5 BIG-IP 13.1.x - 16.1.x"
    strings:
        $path1     = "/mgmt/tm/util/bash"                       ascii nocase
        $path2     = "/mgmt/shared/authn/login"                 ascii nocase
        $header1   = "X-F5-Auth-Token"                          ascii nocase
        $header2   = "Authorization: Basic YWRtaW46"            ascii  // admin:
        $cmd       = "commandChunks"                            ascii
    condition:
        ($path1 and $cmd) or ($header1 and $path1) or $header2
}

// ── Cisco IOS XE WebUI RCE (CVE-2023-20198) ──────────────────────────────────
rule APT_Cisco_IOSXE_CVE_2023_20198 {
    meta:
        description = "Detects Cisco IOS XE WebUI privilege escalation exploit"
        cve         = "CVE-2023-20198"
        severity    = "CRITICAL"
        cvss        = "10.0"
        threat_actor = "Active exploitation in Asia-Pacific"
    strings:
        $path1  = "/webui/logoutconfirm.html"    ascii nocase
        $path2  = "/%2577ebui"                   ascii  // URL obfuscation
        $param1 = "username="                    ascii nocase
        $param2 = "privilege=15"                 ascii nocase
    condition:
        ($path1 or $path2) and ($param1 or $param2)
}

// ── HTTP/2 Rapid Reset DoS (CVE-2023-44487) ──────────────────────────────────
rule DoS_HTTP2_Rapid_Reset_CVE_2023_44487 {
    meta:
        description = "Detects HTTP/2 Rapid Reset DDoS amplification headers"
        cve         = "CVE-2023-44487"
        severity    = "HIGH"
        cvss        = "7.5"
        reference   = "https://www.cisa.gov/news-events/alerts/2023/10/10/http2-rapid-reset-vulnerability-cve-2023-44487"
    strings:
        $rst   = "RST_STREAM"      ascii nocase
        $rapid = "HEADERS"         ascii nocase
    condition:
        #rst > 100 and $rapid
}

// ── MOVEit Transfer SQLi (CVE-2023-34362) ────────────────────────────────────
rule APT_MOVEit_SQLi_CVE_2023_34362 {
    meta:
        description = "Detects CL0P ransomware MOVEit Transfer exploitation"
        cve         = "CVE-2023-34362"
        severity    = "CRITICAL"
        cvss        = "9.8"
        threat_actor = "CL0P ransomware group — actively exploited APAC 2023"
    strings:
        $path1     = "/guestaccess.aspx"          ascii nocase
        $path2     = "/api/v1/files"              ascii nocase
        $sqli1     = "' OR '1'='1"               ascii nocase
        $sqli2     = "; EXEC xp_cmdshell"         ascii nocase
        $webshell  = "human2.aspx"               ascii nocase
    condition:
        ($path1 or $path2) and ($sqli1 or $sqli2 or $webshell)
}

// ── Citrix Bleed (CVE-2023-4966) — APAC government targeted ─────────────────
rule APT_Citrix_Bleed_CVE_2023_4966 {
    meta:
        description = "Detects Citrix Bleed session token hijacking"
        cve         = "CVE-2023-4966"
        severity    = "CRITICAL"
        cvss        = "9.4"
        threat_actor = "LockBit 3.0, multiple threat actors — APAC targets"
    strings:
        $path1   = "/oauth/idp/.well-known/openid-configuration" ascii nocase
        $path2   = "/nf/auth/doAuthentication.do"               ascii nocase
        $header1 = "NSC_AAAC"                                   ascii
        $overflow = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $path1 or $path2 or ($header1 and #overflow > 3)
}

// ── Supply chain / Software skimmer injection ─────────────────────────────────
rule WebSkimmer_Magecart {
    meta:
        description = "Detects Magecart-style JavaScript payment skimmer injection"
        severity    = "CRITICAL"
        reference   = "MAS Payment Card Security Guidelines"
    strings:
        $skim1  = "document.getElementById('cc-number')"      ascii
        $skim2  = "XMLHttpRequest"                             ascii
        $skim3  = "payment-form"                              ascii nocase
        $exfil1 = "atob("                                     ascii
        $exfil2 = "String.fromCharCode("                      ascii
        $exfil3 = "eval(unescape("                            ascii
    condition:
        ($skim1 or $skim2) and ($exfil1 or $exfil2 or $exfil3)
}

// ── Credential stuffing / brute-force telltale ────────────────────────────────
rule Credential_Stuffing_Pattern {
    meta:
        description = "Detects credential stuffing automation markers"
        severity    = "HIGH"
        reference   = "CSA Singapore Cyber Threat Report 2023 — top attack vector"
    strings:
        $tool1  = "python-requests"       ascii nocase
        $tool2  = "Go-http-client"        ascii nocase
        $tool3  = "libcurl"               ascii nocase
        $tool4  = "okhttp"                ascii nocase
        $path1  = "/login"               ascii nocase
        $path2  = "/auth/token"          ascii nocase
        $path3  = "/api/v1/session"      ascii nocase
    condition:
        ($tool1 or $tool2 or $tool3 or $tool4) and ($path1 or $path2 or $path3)
}

// ── SSTI (Server-Side Template Injection) ────────────────────────────────────
rule SSTI_Template_Injection {
    meta:
        description = "Detects Server-Side Template Injection payloads (Jinja2, Twig, Freemarker)"
        severity    = "HIGH"
        cve_ref     = "CWE-94"
    strings:
        $jinja1   = "{{7*7}}"              ascii
        $jinja2   = "{{config}}"           ascii
        $jinja3   = "{{''.__class__}}"     ascii
        $twig1    = "{{_self.env}}"        ascii
        $ftl1     = "<#assign ex="         ascii nocase
        $ftl2     = "freemarker.template"  ascii nocase
        $mvel1    = "@java.lang.Math"      ascii
    condition:
        any of them
}

// ── GraphQL Introspection Attack ──────────────────────────────────────────────
rule GraphQL_Introspection_Abuse {
    meta:
        description = "Detects GraphQL introspection queries used for API recon"
        severity    = "MEDIUM"
    strings:
        $intro1 = "__schema"       ascii
        $intro2 = "__typename"     ascii
        $intro3 = "__type"         ascii
        $oper1  = "query IntrospectionQuery"  ascii
    condition:
        2 of ($intro*, $oper1)
}
