rule Test_SimpleString {
    meta:
        description = "Поиск простой строки 'evil'"
    strings:
        $evil = "evil" nocase
    condition:
        $evil
}

rule Test_HexPattern {
    meta:
        description = "Поиск HEX-паттерна (MZ-заголовок PE-файла)"
    strings:
        $mz = { 4D 5A }
    condition:
        $mz
}

rule Test_Regex {
    meta:
        description = "Поиск через регулярное выражение (IP-адрес)"
    strings:
        $ip = /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/
    condition:
        $ip
}

rule Test_Combined {
    meta:
        description = "Комбинированное правило (строка + размер файла)"
    strings:
        $s1 = "danger"
        $s2 = "warning"
    condition:
        ($s1 or $s2) and filesize < 100KB
}