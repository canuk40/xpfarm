rule upx_packed {
    meta:
        description = "UPX packed binary"
        category = "packers"
    strings:
        $upx_sig = "UPX!" ascii
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $upx_info = "This file is packed with the UPX" ascii
    condition:
        any of them
}

rule vmprotect_packed {
    meta:
        description = "VMProtect packed binary"
        category = "packers"
    strings:
        $vmp0 = ".vmp0" ascii
        $vmp1 = ".vmp1" ascii
        $vmprotect = "VMProtect" ascii
    condition:
        any of them
}

rule themida_packed {
    meta:
        description = "Themida/WinLicense packed binary"
        category = "packers"
    strings:
        $themida = ".themida" ascii
        $winlicense = "WinLicense" ascii
    condition:
        any of them
}

rule aspack_packed {
    meta:
        description = "ASPack packed binary"
        category = "packers"
    strings:
        $aspack = ".aspack" ascii
        $adata = ".adata" ascii
    condition:
        all of them
}
