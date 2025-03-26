rule WannaCry_Detector
{
    meta:
        description = "Detects WannaCry ransomware"
        author = "yiding77"
        date = "2025-03-27"
        version = "1.0"

    strings:
        $s1 = "WannaDecryptor" ascii nocase
        $s2 = "msg/m_failed.bmp" ascii
        $s3 = { 4D 5A 90 00 03 00 00 00 }

    condition:
        all of them
}
