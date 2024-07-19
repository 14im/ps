[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PossibleIncorrectUsageOfRedirectionOperator','')]
class ArchiveInstaller {
    [string] $DownloadDirectory = $(Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders").PSObject.Properties["{374DE290-123F-4565-9164-39C4925E467B}"].Value
    [string] $DownloadUrl
    [string] $GithubRepositoryOwner
    [string] $GithubRepositoryName
    [string] $ArchiveGlob = '*x64.zip'

    static [string] DefaultDestination() {
        return Join-Path -Path $(Join-Path -Path $([environment]::GetFolderPath('LocalApplicationData')) -ChildPath 'Programs') -ChildPath 'Microsoft'
    }

    ArchiveInstaller() {
    }

    ArchiveInstaller([string] $DownloadUrl) {
        $this.DownloadUrl = $DownloadUrl
    }

    ArchiveInstaller([string] $GithubRepositoryOwner, [string] $GithubRepositoryName) {
        $this.GithubRepositoryOwner = $GithubRepositoryOwner
        $this.GithubRepositoryName = $GithubRepositoryName
    }

    ArchiveInstaller([string] $GithubRepositoryOwner, [string] $GithubRepositoryName, [string] $Glob) {
        $this.GithubRepositoryOwner = $GithubRepositoryOwner
        $this.GithubRepositoryName = $GithubRepositoryName
        $this.Glob = $Glob
    }

    [string] Download() {
        if( $null -eq $this.DownloadUrl) {
            if( ($null -ne $this.GithubRepositoryName) -and ( $null -ne $this.GithubRepositoryOwner) ) {
                $this.DownloadUrl = $this.GetGitHubDownloadUrl()
            }
        }
        if( $null -eq $this.DownloadUrl) {
            throw "Download Url is missing"
        }
        $DownloadArchive = Join-Path -Path $this.DownloadDirectory -ChildPath $this.GetDownloadArchive()
        Invoke-WebRequest -Uri $this.DownloadUrl -OutFile $DownloadArchive
        return $DownloadArchive
    }

    [string] GetGitHubDownloadUrl() {
        $release = Invoke-RestMethod "https://api.github.com/repos/$($this.GithubRepositoryOwner)/$($this.GithubRepositoryName)/releases/latest"
        return @($release.assets | Where-Object name -Like $($this.ArchiveGlob))[0].browser_download_url
    }

    [string] GetDownloadArchive() {
        if( $null -eq $this.DownloadUrl) {
            if( ($null -ne $this.GithubRepositoryName) -and ( $null -ne $this.GithubRepositoryOwner) ) {
                $this.DownloadUrl = $this.GetGitHubDownloadUrl()
            }
        }
        if( $null -eq $this.DownloadUrl) {
            throw "Download Url is missing"
        }
        $WebResponseObject = Invoke-WebRequest -Uri $this.DownloadUrl -Method HEAD
        $ContentDisposition = @{}
        $WebResponseObject.Headers.'Content-Disposition' -split ';' | ForEach-Object {
            $pair = $_ -split '='
            $ContentDisposition[$pair[0] -replace '^\s*'] = $pair[1]
        }
        return $ContentDisposition['filename']
    }

    [string] GetLastLocalArchive() {
        $Archive = @(Get-ChildItem -Path $this.DownloadDirectory | Where-Object Name -iLike $this.ArchiveGlob | Sort-Object -Property Name)[-1].Fullname
        return $Archive
    }

    [string] ExtractLastLocalArchive() {
        return this.DestinationExtractionDirectory($this.GetLastLocalArchive())
    }
    
    [string] DestinationExtractionDirectory() {
        $Destination = [ArchiveInstaller]::DefaultDestination()
        $Archive = $this.GetLastLocalArchive()
        $DestinationPath = Join-Path -Path $Destination -ChildPath $((Split-Path -Path $Archive -Leaf) -replace '\.zip$' -replace '\.0_x64$')
        return $DestinationPath
    }
    
    [string] DestinationExtractionDirectory($Archive) {
        $Destination = [ArchiveInstaller]::DefaultDestination()
        $Archive = $this.GetLastLocalArchive()
        $DestinationPath = Join-Path -Path $Destination -ChildPath $((Split-Path -Path $Archive -Leaf) -replace '\.zip$' -replace '\.0_x64$')
        return $DestinationPath
    }
    
    [string] ExtractLastLocalArchive($Destination) {
        if( (Test-Path $Destination) -eq $False ) {
            New-Item -Path $Destination -ItemType Directory
        }
        $Archive = $this.GetLastLocalArchive()
        $DestinationPath = Join-Path -Path $Destination -ChildPath $((Split-Path -Path $Archive -Leaf) -replace '\.zip$' -replace '\.0_x64$')
        Expand-Archive -Path $Archive -DestinationPath $DestinationPath -Force
        return $DestinationPath
    }
}

class PowershellArchiveInstaller : ArchiveInstaller {
    PowershellArchiveInstaller() {
        $this.GithubRepositoryOwner = 'PowerShell'
        $this.GithubRepositoryName = 'PowerShell'
        $this.ArchiveGlob = "PowerShell-*-x64.zip"
    }
}

class VSCodeArchiveInstaller : ArchiveInstaller {
    VSCodeArchiveInstaller() {
        $this.DownloadUrl = 'https://code.visualstudio.com/sha/download?build=stable&os=win32-x64-archive'
        $this.ArchiveGlob = "VSCode-win32-x64-*.zip"
    }
}

class PowershellVSCodeExtensionArchiveInstaller : ArchiveInstaller {
    PowershellVSCodeExtensionArchiveInstaller() {
        $this.GithubRepositoryOwner = 'PowerShell'
        $this.GithubRepositoryName = 'vscode-powershell'
        $this.ArchiveGlob = "powershell-*.vsix"
    }
}

class WindowsTerminalArchiveInstaller : ArchiveInstaller {
    WindowsTerminalArchiveInstaller() {
        $this.GithubRepositoryOwner = 'microsoft'
        $this.GithubRepositoryName = 'terminal'
        $this.ArchiveGlob = "Microsoft.WindowsTerminal_*x64.zip"
    }

    [string] ExtractLastLocalArchive () {
        $Destination = Join-Path -Path $(Join-Path -Path $([environment]::GetFolderPath('LocalApplicationData')) -ChildPath 'Programs') -ChildPath 'Microsoft'
        return $this.ExtractLastLocalArchive($Destination)
    }

    [string] ExtractLastLocalArchive ($Destination) {
        $DestinationPath = ([ArchiveInstaller] $this).ExtractLastLocalArchive($Destination)
        $SubDirectory = Get-ChildItem -Directory $DestinationPath
        Move-Item "$($SubDirectory.FullName)\*" -Destination $DestinationPath
        Remove-Item -Recurse $SubDirectory.FullName
        return $DestinationPath
    }
}

class GitArchiveInstaller : ArchiveInstaller {
    GitArchiveInstaller() {
        $this.GithubRepositoryOwner = 'git-for-windows'
        $this.GithubRepositoryName = 'git'
        $this.ArchiveGlob = '*-64-bit.zip'
    }
}

# stolen from https://stackoverflow.com/questions/69236623/adding-path-permanently-to-windows-using-powershell-doesnt-appear-to-work

function Add-Path {
    param(
      [Parameter(Mandatory, Position=0)]
      [string] $LiteralPath,
      [ValidateSet('User', 'CurrentUser', 'Machine', 'LocalMachine')]
      [string] $Scope 
    )
    Set-StrictMode -Version 1; $ErrorActionPreference = 'Stop'
  
    $isMachineLevel = $Scope -in 'Machine', 'LocalMachine'
    
    if ($isMachineLevel -and -not $($ErrorActionPreference = 'Continue'; net session 2>$null)) { throw "You must run AS ADMIN to update the machine-level Path environment variable." }  
  
    $regPath = 'registry::' + ('HKEY_CURRENT_USER\Environment', 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment')[$isMachineLevel]
  
    # Note the use of the .GetValue() method to ensure that the *unexpanded* value is returned.
    $currDirs = (Get-Item -LiteralPath $regPath).GetValue('Path', '', 'DoNotExpandEnvironmentNames') -split ';' -ne ''
  
    if ($LiteralPath -in $currDirs) {
      Write-Verbose "Already present in the persistent $(('user', 'machine')[$isMachineLevel])-level Path: $LiteralPath"
      return
    }
  
    $newValue = ($currDirs + $LiteralPath) -join ';'
  
    # Update the registry.
    Set-ItemProperty -Type ExpandString -LiteralPath $regPath Path $newValue
  
    # Broadcast WM_SETTINGCHANGE to get the Windows shell to reload the
    # updated environment, via a dummy [Environment]::SetEnvironmentVariable() operation.
    $dummyName = [guid]::NewGuid().ToString()
    [Environment]::SetEnvironmentVariable($dummyName, 'foo', 'User')
    [Environment]::SetEnvironmentVariable($dummyName, [NullString]::value, 'User')
  
    # Finally, also update the current session's `$env:Path` definition.
    # Note: For simplicity, we always append to the in-process *composite* value,
    #        even though for a -Scope Machine update this isn't strictly the same.
    $env:Path = ($env:Path -replace ';$') + ';' + $LiteralPath
  
    Write-Verbose "`"$LiteralPath`" successfully appended to the persistent $(('user', 'machine')[$isMachineLevel])-level Path and also the current-process value."
  
  }
function Get-PowerShellArchive {
    param(
        $DownloadDirectory
    )
    $ArchiveInstaller = [PowershellArchiveInstaller]::new()
    if( $null -ne $DownloadDirectory ) {
        $ArchiveInstaller.DownloadDirectory = $DownloadDirectory
    }
    $ArchiveInstaller.Download()
}

function Expand-PowerShellArchive {
    param(
        $DownloadDirectory,
        [switch]$AddPath = [switch]::Present
    )
    $ArchiveInstaller = [PowershellArchiveInstaller]::new()
    if( $null -ne $DownloadDirectory ) {
        $ArchiveInstaller.DownloadDirectory = $DownloadDirectory
    }
    $DestinationDirectory = $ArchiveInstaller.ExtractLastLocalArchive()
    if( $AddPath -eq [switch]::Present) {
        $BinDirectory = $DestinationDirectory
        Add-Path -LiteralPath $BinDirectory -Scope CurrentUser
    }
    $DestinationDirectory
}

function Get-VSCodeArchive {
    param(
        $DownloadDirectory
    )
    $ArchiveInstaller = [VSCodeArchiveInstaller]::new()
    if( $null -ne $DownloadDirectory ) {
        $ArchiveInstaller.DownloadDirectory = $DownloadDirectory
    }
    $ArchiveInstaller.Download()
}

function Expand-VSCodeArchive {
    param(
        $DownloadDirectory,
        [switch]$AddPath = [switch]::Present
    )
    $ArchiveInstaller = [VSCodeArchiveInstaller]::new()
    if( $null -ne $DownloadDirectory ) {
        $ArchiveInstaller.DownloadDirectory = $DownloadDirectory
    }
    $DestinationDirectory = $ArchiveInstaller.ExtractLastLocalArchive()
    if( $AddPath -eq [switch]::Present) {
        $BinDirectory = $DestinationDirectory
        Add-Path -LiteralPath $BinDirectory -Scope CurrentUser
    }
    $DestinationDirectory
}

function Get-WindowsTerminalArchive {
    param(
        $DownloadDirectory
    )
    $ArchiveInstaller = [WindowsTerminalArchiveInstaller]::new()
    if( $null -ne $DownloadDirectory ) {
        $ArchiveInstaller.DownloadDirectory = $DownloadDirectory
    }
    $ArchiveInstaller.Download()
}

function Expand-WindowsTerminalArchive {
    param(
        $DownloadDirectory,
        [switch]$AddPath = [switch]::Present
    )
    $ArchiveInstaller = [WindowsTerminalArchiveInstaller]::new()
    if( $null -ne $DownloadDirectory ) {
        $ArchiveInstaller.DownloadDirectory = $DownloadDirectory
    }
    $DestinationDirectory = $ArchiveInstaller.ExtractLastLocalArchive()
    if( $AddPath -eq [switch]::Present) {
        $BinDirectory = $DestinationDirectory
        Add-Path -LiteralPath $BinDirectory -Scope CurrentUser
    }
    $DestinationDirectory
}

function Get-PowershellVSCodeExtension {
    param(
        $DownloadDirectory
    )
    $ArchiveInstaller = [PowershellVSCodeExtensionArchiveInstaller]::new()
    if( $null -ne $DownloadDirectory ) {
        $ArchiveInstaller.DownloadDirectory = $DownloadDirectory
    }
    $ArchiveInstaller.Download()
}

function Install-PowershellVSCodeExtension {
    param(
        $DownloadDirectory,
        $VSCodeDirectory = ([VSCodeArchiveInstaller]::new()).DestinationExtractionDirectory(),
        [switch]$Portable = [switch]::Present
    )
    $VSCodeLauncher = Join-Path -Path (Join-Path -Path $VSCodeDirectory -ChildPath 'bin' ) -ChildPath 'code.cmd'
    if( (Test-Path -Path $VSCodeLauncher) -eq $false) {
        Throw "vscode missing"
    }
    $ArchiveInstaller = [PowershellVSCodeExtensionArchiveInstaller]::new()
    if( $null -ne $DownloadDirectory ) {
        $ArchiveInstaller.DownloadDirectory = $DownloadDirectory
    }
    if( $Portable -eq  [switch]::Present) {
        $DataDirectory = Join-Path -Path $VSCodeDirectory -ChildPath 'data'
        if( (Test-Path -Path $DataDirectory) -eq $false ) {
            New-Item -Type Directory -Path $DataDirectory
        }
    }
    $zip = [IO.Compression.ZipFile]::OpenRead($ArchiveInstaller.GetLastLocalArchive())
    $entry = $zip.Entries | Where-Object Name -EQ 'extension.vsixmanifest'
    $stream = $entry.Open()
    $reader = New-Object -TypeName System.IO.StreamReader -ArgumentList $stream
    $content = $reader.ReadToEnd()
    $reader.Dispose()
    $stream.Dispose()
    $zip.Dispose()
    $xml = [xml]$content
    $extensionID = '{0}.{1}' -f ($xml.PackageManifest.Metadata.Identity.Publisher,$xml.PackageManifest.Metadata.Identity.Id)
    $InstalledExtensions = & $VSCodeLauncher --list-extensions
    if( $InstalledExtensions -split "`n" -notcontains $extensionID ) {
        $commandLine = '/c {0} --install-extension {1}' -f ($VSCodeLauncher, $ArchiveInstaller.GetLastLocalArchive())
        Start-Process -FilePath 'cmd' -ArgumentList $commandLine -Wait    
    } else {
        Write-Verbose "Extension ""$($extensionID)"" allready installed"
    }
}

function Get-Git {
    param(
        $DownloadDirectory
    )
    $ArchiveInstaller = [GitArchiveInstaller]::new()
    if( $null -ne $DownloadDirectory ) {
        $ArchiveInstaller.DownloadDirectory = $DownloadDirectory
    }
    $ArchiveInstaller.Download()
}

function Install-Git {
    param(
        $DownloadDirectory,
        [switch]$AddPath = [switch]::Present
    )
    $ArchiveInstaller = [GitArchiveInstaller]::new()
    $DestinationDirectory = $ArchiveInstaller.ExtractLastLocalArchive()
    if( $AddPath -eq [switch]::Present) {
        $BinDirectory = Join-Path -Path  $(Join-Path -Path $DestinationDirectory -ChildPath 'mingw64') -ChildPath 'bin'
        Add-Path -LiteralPath $BinDirectory -Scope CurrentUser    
    }
    $Destination
}
