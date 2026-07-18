function Import-PunaroEnvironment {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Punaro configuration is unavailable: $Path"
    }
    foreach ($line in [System.IO.File]::ReadAllLines($Path)) {
        if ([string]::IsNullOrWhiteSpace($line) -or $line.TrimStart().StartsWith('#')) {
            continue
        }
        $separator = $line.IndexOf('=')
        if ($separator -le 0) {
            throw 'Punaro configuration contains an invalid line'
        }
        $name = $line.Substring(0, $separator)
        if ($name -notmatch '^PUNARO_[A-Z0-9_]+$') {
            throw 'Punaro configuration contains an invalid variable name'
        }
        [System.Environment]::SetEnvironmentVariable($name, $line.Substring($separator + 1), 'Process')
    }
}
