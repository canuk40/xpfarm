rule aes_sbox {
    meta:
        description = "AES S-box constant detected"
        category = "crypto"
    strings:
        // First 16 bytes of AES S-box
        $sbox = { 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76 }
        // AES inverse S-box first 16 bytes
        $inv_sbox = { 52 09 6A D5 30 36 A5 38 BF 40 A3 9E 81 F3 D7 FB }
    condition:
        any of them
}

rule aes_string {
    meta:
        description = "AES string references detected"
        category = "crypto"
    strings:
        $aes1 = "AES" ascii wide
        $aes2 = "aes" ascii
        $rijndael = "Rijndael" ascii nocase
        $aes_cbc = "AES-CBC" ascii
        $aes_gcm = "AES-GCM" ascii
        $aes_ctr = "AES-CTR" ascii
    condition:
        any of them
}

rule rsa_constants {
    meta:
        description = "RSA implementation indicators"
        category = "crypto"
    strings:
        $rsa1 = "RSA" ascii wide
        $rsa_pub = "BEGIN RSA PUBLIC KEY" ascii
        $rsa_priv = "BEGIN RSA PRIVATE KEY" ascii
        $mod_exp = "mod_exp" ascii
        $modpow = "modPow" ascii
    condition:
        any of them
}

rule des_constants {
    meta:
        description = "DES/3DES constants detected"
        category = "crypto"
    strings:
        // DES initial permutation table (first 8 bytes as pattern)
        $des_ip = { 3A 32 2A 22 1A 12 0A 02 }
        $des_str = "DES" ascii wide
        $triple_des = "3DES" ascii
        $des_ede = "DES-EDE" ascii
    condition:
        any of them
}

rule rc4_indicators {
    meta:
        description = "RC4/ARC4 implementation indicators"
        category = "crypto"
    strings:
        $rc4 = "RC4" ascii wide
        $arc4 = "ARC4" ascii wide
        $arcfour = "ARCFOUR" ascii nocase
    condition:
        any of them
}

rule chacha_constants {
    meta:
        description = "ChaCha20/Salsa20 constants"
        category = "crypto"
    strings:
        // "expand 32-byte k" - ChaCha/Salsa constant
        $expand = "expand 32-byte k" ascii
        // "expand 16-byte k"
        $expand16 = "expand 16-byte k" ascii
        $chacha = "ChaCha" ascii
        $salsa = "Salsa20" ascii
    condition:
        any of them
}

rule sha_constants {
    meta:
        description = "SHA hash function constants"
        category = "crypto"
    strings:
        // SHA-256 initial hash values (first 4 bytes of h0)
        $sha256_h0 = { 67 E6 09 6A }
        $sha_str = "SHA-256" ascii
        $sha1_str = "SHA-1" ascii
        $sha512_str = "SHA-512" ascii
    condition:
        any of them
}
