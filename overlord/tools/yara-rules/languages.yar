rule rust_binary {
    meta:
        description = "Detects Rust compiled binaries"
        category = "languages"
    strings:
        $rust_panic = "rust_panic" ascii
        $core_fmt = "core::fmt" ascii
        $std_io = "std::io" ascii
        $rust_begin = "rust_begin_unwind" ascii
        $core_result = "core::result" ascii
        $alloc_alloc = "alloc::alloc" ascii
        $core_ops = "core::ops" ascii
        $std_thread = "std::thread" ascii
    condition:
        2 of them
}

rule go_binary {
    meta:
        description = "Detects Go compiled binaries"
        category = "languages"
    strings:
        $go_buildid = "go.buildid" ascii
        $runtime_go = "runtime.go" ascii
        $fmt_print = "fmt.Print" ascii
        $main_main = "main.main" ascii
        $runtime_goexit = "runtime.goexit" ascii
        $gosched = "runtime.Gosched" ascii
    condition:
        2 of them
}

rule zig_binary {
    meta:
        description = "Detects Zig compiled binaries"
        category = "languages"
    strings:
        $std_io = "std.io" ascii
        $std_fmt = "std.fmt" ascii
        $std_heap = "std.heap" ascii
        $std_mem = "std.mem" ascii
        $std_debug = "std.debug" ascii
    condition:
        2 of them
}

rule nim_binary {
    meta:
        description = "Detects Nim compiled binaries"
        category = "languages"
    strings:
        $nim_main = "NimMain" ascii
        $nim_gc = "nimGC" ascii
        $system_nim = "system.nim" ascii
    condition:
        2 of them
}

rule dotnet_binary {
    meta:
        description = "Detects .NET/Mono binaries"
        category = "languages"
    strings:
        $mscoree = "mscoree.dll" ascii nocase
        $clr = "_CorExeMain" ascii
        $mscorlib = "mscorlib" ascii
    condition:
        any of them
}
