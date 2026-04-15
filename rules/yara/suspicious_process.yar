rule SuspiciousProcess : malware apt {
    meta:
        author = "IntrusionScope"
        description = "Detects suspicious process execution patterns"
        severity = "high"
        date = "2024-01-01"
    
    strings:
        $ps1 = "powershell" ascii wide nocase
        $enc = "-enc" ascii
        $download = "DownloadString" ascii wide
        $invoke = "Invoke-Expression" ascii wide
        $bypass = "-ExecutionPolicy Bypass" ascii wide
        
    condition:
        any of them
}
