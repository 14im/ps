class ArchiveInstaller {
    [string] $DownloadDirectory = $(Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders").PSObject.Properties["{374DE290-123F-4565-9164-39C4925E467B}"].Value
    [string] $DownloadUrl
    [string] $GithubRepositoryOwner
    [string] $GithubRepositoryName
    [string] $ArchiveGlob = '*x64.zip'

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

    [string] Download () {
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

    [string] GetGitHubDownloadUrl () {
        $release = Invoke-RestMethod "https://api.github.com/repos/$($this.GithubRepositoryOwner)/$($this.GithubRepositoryName)/releases/latest"
        return ($release.assets | Where-Object name -Like $($this.ArchiveGlob)).browser_download_url
    }

    [string] GetDownloadArchive () {
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

    [string] GetLastLocalArchive () {
        $Archive = @(Get-ChildItem -Path $this.DownloadDirectory | Where-Object Name -iLike $this.ArchiveGlob | Sort-Object -Property Name)[-1].Fullname
        return $Archive
    }

    [string] ExtractLastLocalArchive () {
        $Destination = Join-Path -Path $(Join-Path -Path $([environment]::GetFolderPath('LocalApplicationData')) -ChildPath 'Programs') -ChildPath 'Microsoft'
        return $this.ExtractLastLocalArchive($Destination)
    }
    
    [string] ExtractLastLocalArchive ($Destination) {
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
        Remove-Item $SubDirectory.FullName
        return $DestinationPath
    }
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
        $DownloadDirectory
    )
    $ArchiveInstaller = [PowershellArchiveInstaller]::new()
    if( $null -ne $DownloadDirectory ) {
        $ArchiveInstaller.DownloadDirectory = $DownloadDirectory
    }
   $ArchiveInstaller.ExtractLastLocalArchive()
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
        $DownloadDirectory
    )
    $ArchiveInstaller = [VSCodeArchiveInstaller]::new()
    if( $null -ne $DownloadDirectory ) {
        $ArchiveInstaller.DownloadDirectory = $DownloadDirectory
    }
   $ArchiveInstaller.ExtractLastLocalArchive()
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
        $DownloadDirectory
    )
    $ArchiveInstaller = [WindowsTerminalArchiveInstaller]::new()
    if( $null -ne $DownloadDirectory ) {
        $ArchiveInstaller.DownloadDirectory = $DownloadDirectory
    }
   $ArchiveInstaller.ExtractLastLocalArchive()
}

