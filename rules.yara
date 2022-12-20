rule remove_root_directory {
    strings:
        $s = "b"
    condition:
        $s
}