param(
    [string]$BundleRoot = ".\vm_bundle",
    [string]$OutputPath = "environment_profile.json",
    [string[]]$RegistryPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    ),
    [string[]]$ModuleNames = @(
        "ntdll.dll",
        "kernel32.dll",
        "kernelbase.dll",
        "user32.dll",
        "gdi32.dll",
        "shell32.dll",
        "shlwapi.dll",
        "lpk.dll",
        "usp10.dll",
        "advapi32.dll",
        "msvcrt.dll",
        "ws2_32.dll",
        "psapi.dll"
    ),
    [string[]]$ExtraModulePaths = @(),
    [string[]]$EnvironmentVariableNames = @(
        "APPDATA",
        "COMSPEC",
        "COMMONPROGRAMFILES",
        "COMMONPROGRAMFILES(X86)",
        "HOMEDRIVE",
        "HOMEPATH",
        "LOCALAPPDATA",
        "NUMBER_OF_PROCESSORS",
        "OS",
        "PATH",
        "PATHEXT",
        "PROCESSOR_ARCHITECTURE",
        "PROCESSOR_IDENTIFIER",
        "PROCESSOR_LEVEL",
        "PROCESSOR_REVISION",
        "PROGRAMDATA",
        "PROGRAMFILES",
        "PROGRAMFILES(X86)",
        "PUBLIC",
        "SESSIONNAME",
        "SYSTEMDRIVE",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "USERDOMAIN",
        "USERNAME",
        "USERPROFILE",
        "WINDIR"
    ),
    [int]$ProcessLimit = 64,
    [switch]$CopySysWOW64,
    [string]$ProcessImagePath = "",
    [string]$CommandLine = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

try {
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
} catch {
}

function Get-FullPath {
    param(
        [string]$BasePath,
        [string]$Path
    )

    if ([IO.Path]::IsPathRooted($Path)) {
        return [IO.Path]::GetFullPath($Path)
    }
    return [IO.Path]::GetFullPath((Join-Path $BasePath $Path))
}

function Get-RelativePathCompat {
    param(
        [string]$BasePath,
        [string]$TargetPath
    )

    $baseUri = New-Object System.Uri(([IO.Path]::GetFullPath($BasePath).TrimEnd('\') + '\'))
    $targetUri = New-Object System.Uri([IO.Path]::GetFullPath($TargetPath))
    $relativeUri = $baseUri.MakeRelativeUri($targetUri)
    [System.Uri]::UnescapeDataString($relativeUri.ToString()).Replace('/', '\')
}

function Convert-RegistryPath {
    param([string]$Path)
    if ($Path.StartsWith("HKLM:\")) { return "HKEY_LOCAL_MACHINE\" + $Path.Substring(5) }
    if ($Path.StartsWith("HKCU:\")) { return "HKEY_CURRENT_USER\" + $Path.Substring(5) }
    if ($Path.StartsWith("HKCR:\")) { return "HKEY_CLASSES_ROOT\" + $Path.Substring(5) }
    if ($Path.StartsWith("HKU:\"))  { return "HKEY_USERS\" + $Path.Substring(4) }
    if ($Path.StartsWith("HKCC:\")) { return "HKEY_CURRENT_CONFIG\" + $Path.Substring(5) }
    return $Path
}

function Get-RegistryValueRecord {
    param(
        [Microsoft.Win32.RegistryKey]$Key,
        [string]$Name
    )

    $kind = $Key.GetValueKind($Name)
    $value = $Key.GetValue($Name, $null, "DoNotExpandEnvironmentNames")
    $record = [ordered]@{
        name = $Name
        value_type = 0
    }

    switch ($kind) {
        "String" {
            $record.value_type = 1
            $record.string = [string]$value
        }
        "ExpandString" {
            $record.value_type = 2
            $record.string = [string]$value
        }
        "Binary" {
            $record.value_type = 3
            $record.binary_hex = (($value | ForEach-Object { $_.ToString("X2") }) -join "")
        }
        "DWord" {
            $record.value_type = 4
            $record.dword = [uint32]$value
        }
        "MultiString" {
            $record.value_type = 7
            $record.multi_string = @($value)
        }
        "QWord" {
            $record.value_type = 11
            $record.qword = [uint64]$value
        }
        default {
            return $null
        }
    }

    return [pscustomobject]$record
}

function Export-RegistryTree {
    param([string]$Path)

    $items = New-Object System.Collections.Generic.List[object]
    foreach ($item in @(Get-Item -Path $Path), @(Get-ChildItem -Path $Path -Recurse -ErrorAction SilentlyContinue)) {
        if (-not $item) { continue }
        $key = $item.OpenSubKey("")
        if (-not $key) { continue }

        $values = New-Object System.Collections.Generic.List[object]
        foreach ($name in $key.GetValueNames()) {
            $record = Get-RegistryValueRecord -Key $key -Name $name
            if ($record) { $values.Add($record) }
        }

        $items.Add([pscustomobject]@{
            path = Convert-RegistryPath $item.PSPath.Replace("Microsoft.PowerShell.Core\Registry::", "")
            values = @($values)
        })
    }

    return @($items)
}

function Get-EnvironmentVariableRecords {
    param([string[]]$Names)

    $records = New-Object System.Collections.Generic.List[object]
    foreach ($name in ($Names | Sort-Object -Unique)) {
        if (-not $name) { continue }
        $value = [Environment]::GetEnvironmentVariable($name)
        if ($null -eq $value -or $value -eq "") { continue }
        $records.Add([pscustomobject]@{
            name = $name
            value = [string]$value
        })
    }
    return @($records)
}

function Get-ProcessSnapshotRecords {
    param([int]$Limit)

    $records = New-Object System.Collections.Generic.List[object]
    $processes = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Sort-Object ProcessId |
        Select-Object -First $Limit
    foreach ($process in $processes) {
        if (-not $process.ProcessId) { continue }
        $imagePath = if ($process.ExecutablePath) { [string]$process.ExecutablePath } else { "" }
        $commandLine = if ($process.CommandLine) { [string]$process.CommandLine } else { $imagePath }
        $currentDirectory = if ($imagePath) { Split-Path -Parent $imagePath } else { "" }
        $records.Add([pscustomobject]@{
            pid = [uint32]$process.ProcessId
            parent_pid = [uint32]$process.ParentProcessId
            image_path = $imagePath
            command_line = $commandLine
            current_directory = $currentDirectory
        })
    }
    return @($records)
}

function Copy-ModuleFiles {
    param(
        [string]$SourceDirectory,
        [string]$TargetDirectory,
        [string[]]$Names
    )

    if (-not (Test-Path -LiteralPath $SourceDirectory)) {
        return @()
    }

    New-Item -ItemType Directory -Force -Path $TargetDirectory | Out-Null
    $copied = New-Object System.Collections.Generic.List[string]
    foreach ($moduleName in ($Names | Sort-Object -Unique)) {
        if (-not $moduleName) { continue }
        $source = Join-Path $SourceDirectory $moduleName
        if (-not (Test-Path -LiteralPath $source)) { continue }
        Copy-Item -LiteralPath $source -Destination (Join-Path $TargetDirectory ([IO.Path]::GetFileName($moduleName))) -Force
        $copied.Add($moduleName)
    }
    return @($copied)
}

function Copy-ExplicitModuleFiles {
    param(
        [string[]]$Paths,
        [string]$TargetDirectory
    )

    if (-not $Paths -or $Paths.Count -eq 0) {
        return @()
    }

    New-Item -ItemType Directory -Force -Path $TargetDirectory | Out-Null
    $copied = New-Object System.Collections.Generic.List[string]
    foreach ($path in $Paths) {
        if (-not $path) { continue }
        if (-not (Test-Path -LiteralPath $path)) { continue }
        $target = Join-Path $TargetDirectory ([IO.Path]::GetFileName($path))
        Copy-Item -LiteralPath $path -Destination $target -Force
        $copied.Add($target)
    }
    return @($copied)
}

$resolvedBundleRoot = Get-FullPath -BasePath (Get-Location).Path -Path $BundleRoot
New-Item -ItemType Directory -Force -Path $resolvedBundleRoot | Out-Null
$resolvedOutputPath = Get-FullPath -BasePath $resolvedBundleRoot -Path $OutputPath
$outputDirectory = Split-Path -Parent $resolvedOutputPath
if ($outputDirectory) {
    New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null
}

$profileBaseDirectory = Split-Path -Parent $resolvedOutputPath
$moduleSearchPaths = New-Object System.Collections.Generic.List[string]
$copiedModuleCount = 0

$systemRoot = $env:SystemRoot
$system32 = Join-Path $systemRoot "System32"
$syswow64 = Join-Path $systemRoot "SysWOW64"
$dllRoot = Join-Path $resolvedBundleRoot "dlls"
$snapshotSystem32 = Join-Path $dllRoot "System32"
$snapshotSysWOW64 = Join-Path $dllRoot "SysWOW64"
$snapshotExtra = Join-Path $dllRoot "Extra"

$copiedSystem32 = Copy-ModuleFiles -SourceDirectory $system32 -TargetDirectory $snapshotSystem32 -Names $ModuleNames
if ($copiedSystem32.Count -gt 0) {
    $moduleSearchPaths.Add((Get-RelativePathCompat -BasePath $profileBaseDirectory -TargetPath $snapshotSystem32))
    $copiedModuleCount += $copiedSystem32.Count
}

if ($CopySysWOW64 -and (Test-Path -LiteralPath $syswow64)) {
    $copiedWow64 = Copy-ModuleFiles -SourceDirectory $syswow64 -TargetDirectory $snapshotSysWOW64 -Names $ModuleNames
    if ($copiedWow64.Count -gt 0) {
        $moduleSearchPaths.Add((Get-RelativePathCompat -BasePath $profileBaseDirectory -TargetPath $snapshotSysWOW64))
        $copiedModuleCount += $copiedWow64.Count
    }
}

$copiedExplicit = Copy-ExplicitModuleFiles -Paths $ExtraModulePaths -TargetDirectory $snapshotExtra
if ($copiedExplicit.Count -gt 0) {
    $moduleSearchPaths.Add((Get-RelativePathCompat -BasePath $profileBaseDirectory -TargetPath $snapshotExtra))
    $copiedModuleCount += $copiedExplicit.Count
}

$moduleSearchPaths = @($moduleSearchPaths | Sort-Object -Unique)

$computerName = [Environment]::MachineName
$userName = $env:USERNAME
$userDomain = if ($env:USERDOMAIN) { $env:USERDOMAIN } else { "WORKGROUP" }
$tempDir = [IO.Path]::GetTempPath().TrimEnd('\')
$currentDirectory = (Get-Location).Path
$explorer = Get-Process explorer -ErrorAction SilentlyContinue | Select-Object -First 1
$parentPid = if ($explorer) { [uint32]$explorer.Id } else { 0 }
$parentImage = if ($explorer) { [string]$explorer.Path } else { "" }

$os = Get-CimInstance Win32_OperatingSystem
$versionParts = ($os.Version -split '\.')
$major = [uint32]$versionParts[0]
$minor = [uint32]$versionParts[1]
$build = [uint32]$os.BuildNumber
$buildLabEx = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction SilentlyContinue).BuildLabEx

$screenWidth = 1920
$screenHeight = 1080
$cursorX = 317
$cursorY = 31
if ([System.Management.Automation.PSTypeName]'System.Windows.Forms.Screen'.Type) {
    $bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
    $screenWidth = [int]$bounds.Width
    $screenHeight = [int]$bounds.Height
    $cursorPosition = [System.Windows.Forms.Cursor]::Position
    $cursorX = [int]$cursorPosition.X
    $cursorY = [int]$cursorPosition.Y
}

$systemDrive = $env:SystemDrive
$logicalDisk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$systemDrive'" -ErrorAction SilentlyContinue
$volumeLabel = if ($logicalDisk -and $logicalDisk.VolumeName) { [string]$logicalDisk.VolumeName } else { "System" }
$fileSystem = if ($logicalDisk -and $logicalDisk.FileSystem) { [string]$logicalDisk.FileSystem } else { "NTFS" }

$serial = 0
$volOutput = cmd /c "vol $systemDrive" 2>$null
if ($volOutput -match "([A-F0-9]{4})-([A-F0-9]{4})") {
    $serial = [Convert]::ToUInt32(($matches[1] + $matches[2]), 16)
}

$registryKeys = New-Object System.Collections.Generic.List[object]
foreach ($path in $RegistryPaths) {
    foreach ($entry in Export-RegistryTree -Path $path) {
        $registryKeys.Add($entry)
    }
}

$environmentVariables = Get-EnvironmentVariableRecords -Names $EnvironmentVariableNames
$processRecords = Get-ProcessSnapshotRecords -Limit $ProcessLimit
$remoteSession = $false
if ($env:SESSIONNAME -and $env:SESSIONNAME.ToUpperInvariant().StartsWith("RDP-")) {
    $remoteSession = $true
}

$profile = [ordered]@{
    machine = [ordered]@{
        computer_name = $computerName
        user_name = $userName
        user_domain = $userDomain
        process_id = 0x1337
        image_path = $ProcessImagePath
        parent_process_id = $parentPid
        parent_image_path = $parentImage
        parent_command_line = if ($parentImage) { $parentImage } else { "" }
        system_root = $systemRoot
        system32 = $system32
        temp_dir = $tempDir
        current_directory = $currentDirectory
        command_line = $CommandLine
    }
    os_version = [ordered]@{
        major = $major
        minor = $minor
        build = $build
        platform_id = 2
        suite_mask = if ($os.SuiteMask) { [uint16]$os.SuiteMask } else { 0 }
        product_type = if ($os.ProductType) { [byte]$os.ProductType } else { 1 }
        service_pack_major = 0
        service_pack_minor = 0
        csd_version = if ($os.CSDVersion) { [string]$os.CSDVersion } else { "" }
        product_name = [string]$os.Caption
        build_lab_ex = if ($buildLabEx) { [string]$buildLabEx } else { "" }
    }
    locale = [ordered]@{
        acp = [System.Text.Encoding]::Default.CodePage
        oemcp = [System.Globalization.CultureInfo]::CurrentCulture.TextInfo.OEMCodePage
        console_cp = [Console]::InputEncoding.CodePage
        console_output_cp = [Console]::OutputEncoding.CodePage
        user_default_lcid = [System.Globalization.CultureInfo]::CurrentCulture.LCID
        thread_locale = [System.Globalization.CultureInfo]::CurrentUICulture.LCID
        system_default_ui_language = [System.Globalization.CultureInfo]::InstalledUICulture.LCID
        user_default_ui_language = [System.Globalization.CultureInfo]::CurrentUICulture.LCID
    }
    display = [ordered]@{
        desktop_window_handle = 0x00100000
        active_window_handle = 0x00100010
        shell_window_handle = 0x00100020
        default_dc_handle = 0x00120000
        screen_width = $screenWidth
        screen_height = $screenHeight
        cursor_x = $cursorX
        cursor_y = $cursorY
        message_x = $cursorX
        message_y = $cursorY
        message_step_x = 0
        message_step_y = 0
        remote_session = $remoteSession
    }
    volume = [ordered]@{
        root_path = "$systemDrive\"
        volume_name = $volumeLabel
        serial = $serial
        max_component_length = 255
        flags = 0x000700FF
        fs_name = $fileSystem
    }
    module_search_paths = @($moduleSearchPaths)
    environment_variables = @($environmentVariables)
    processes = @($processRecords)
    registry = [ordered]@{
        keys = @($registryKeys)
    }
}

$json = $profile | ConvertTo-Json -Depth 10
$json | Set-Content -Path $resolvedOutputPath -Encoding UTF8
Write-Host "Wrote environment profile to $resolvedOutputPath"
Write-Host "Copied $copiedModuleCount modules into $dllRoot"
