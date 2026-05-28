/*
 * AISS YARA Rules — Data Loss Prevention (DLP)
 * Detects sensitive data being uploaded or exfiltrated
 */

rule DLP_CreditCard_Visa {
    meta:
        description = "Detects Visa credit card numbers"
        severity    = "HIGH"
        compliance  = "PCI-DSS"
    strings:
        $visa = /\b4[0-9]{12}(?:[0-9]{3})?\b/
    condition:
        $visa
}

rule DLP_CreditCard_Mastercard {
    meta:
        description = "Detects Mastercard credit card numbers"
        severity    = "HIGH"
        compliance  = "PCI-DSS"
    strings:
        $mc = /\b5[1-5][0-9]{14}\b/
    condition:
        $mc
}

rule DLP_CreditCard_Amex {
    meta:
        description = "Detects American Express credit card numbers"
        severity    = "HIGH"
        compliance  = "PCI-DSS"
    strings:
        $amex = /\b3[47][0-9]{13}\b/
    condition:
        $amex
}

rule DLP_SSN_US {
    meta:
        description = "Detects US Social Security Numbers"
        severity    = "CRITICAL"
        compliance  = "GDPR,HIPAA"
    strings:
        $ssn = /\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/
    condition:
        $ssn
}

rule DLP_AWS_AccessKey {
    meta:
        description = "Detects AWS Access Key IDs"
        severity    = "CRITICAL"
    strings:
        $key = /\bAKIA[0-9A-Z]{16}\b/
    condition:
        $key
}

rule DLP_AWS_SecretKey {
    meta:
        description = "Detects AWS Secret Access Keys"
        severity    = "CRITICAL"
    strings:
        $context  = /aws[_\-\s]?secret/      nocase ascii
        $secret   = /[A-Za-z0-9\/\+]{40}/   ascii
    condition:
        $context and $secret
}

rule DLP_PrivateKey_PEM {
    meta:
        description = "Detects PEM-encoded private key files being uploaded"
        severity    = "CRITICAL"
    strings:
        $rsa   = "-----BEGIN RSA PRIVATE KEY-----"     ascii
        $pkcs8 = "-----BEGIN PRIVATE KEY-----"         ascii
        $ec    = "-----BEGIN EC PRIVATE KEY-----"      ascii
        $dsa   = "-----BEGIN DSA PRIVATE KEY-----"     ascii
        $pgp   = "-----BEGIN PGP PRIVATE KEY BLOCK-----" ascii
    condition:
        any of them
}

rule DLP_GitHub_Token {
    meta:
        description = "Detects GitHub personal access tokens"
        severity    = "CRITICAL"
    strings:
        $ghp  = /ghp_[0-9a-zA-Z]{36}/       ascii  // classic token
        $gho  = /gho_[0-9a-zA-Z]{36}/       ascii  // oauth token
        $ghs  = /ghs_[0-9a-zA-Z]{36}/       ascii  // app installation
        $ghr  = /ghr_[0-9a-zA-Z]{36}/       ascii  // refresh token
    condition:
        any of them
}

rule DLP_Generic_API_Key {
    meta:
        description = "Detects generic API key assignment patterns"
        severity    = "HIGH"
    strings:
        $api_key1 = /(?i)api[_\-\s]?key\s*[=:]\s*["']?[A-Za-z0-9_\-]{20,64}/  ascii
        $api_key2 = /(?i)secret[_\-\s]?key\s*[=:]\s*["']?[A-Za-z0-9_\-]{20,64}/ ascii
        $token1   = /(?i)bearer\s+[A-Za-z0-9\-._~+\/]{20,}/                     ascii
    condition:
        any of them
}

rule DLP_Email_Bulk {
    meta:
        description = "Detects bulk email address exfiltration (10+ emails in payload)"
        severity    = "MEDIUM"
        compliance  = "GDPR"
    strings:
        $email = /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/
    condition:
        #email >= 10
}

rule DLP_Database_Credentials {
    meta:
        description = "Detects database connection strings with credentials"
        severity    = "CRITICAL"
    strings:
        $mysql    = /mysql:\/\/[^:]+:[^@]+@/        ascii nocase
        $postgres = /postgres:\/\/[^:]+:[^@]+@/     ascii nocase
        $mongodb  = /mongodb:\/\/[^:]+:[^@]+@/      ascii nocase
        $redis    = /redis:\/\/:?[^\s@]+@/          ascii nocase
    condition:
        any of them
}
