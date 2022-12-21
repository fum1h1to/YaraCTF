rule yaractf {
    strings:
        $s = "b"
    condition:
        $s
}