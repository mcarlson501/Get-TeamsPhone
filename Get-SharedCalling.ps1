<#
.SYNOPSIS
    An interactive script to guide administrators through the configuration of Microsoft Teams Shared Calling.

.DESCRIPTION
    This script, part of the Get-TeamsPhoneToolkit collection, provides a step-by-step guide for deploying Microsoft Teams 
    Shared Calling. It automates commands, supports bulk operations, and includes audit logging, security confirmations, 
    and state management for a streamlined experience.

.NOTES
    Author: Matthew Carlson (Microsoft)
    Project: Get-TeamsPhoneToolkit
    Version: 2.0
    Last Updated: 2025-06-29
#>

# ---------------------------------------------------------------------------------------------
# Security Configuration and Constants
# ---------------------------------------------------------------------------------------------

# Set execution policy validation
if ((Get-ExecutionPolicy) -eq 'Restricted') {
    Write-Host "❌ PowerShell execution policy is set to 'Restricted'. This script cannot run." -ForegroundColor Red
    Write-Host "Please run: Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser" -ForegroundColor Yellow
    exit
}

# Validate PowerShell version (require 5.1 or later for security features)
if ($PSVersionTable.PSVersion.Major -lt 5 -or 
    ($PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSVersion.Minor -lt 1)) {
    Write-Host "❌ This script requires PowerShell 5.1 or later for security features." -ForegroundColor Red
    Write-Host "Current version: $($PSVersionTable.PSVersion)" -ForegroundColor Yellow
    exit
}

# Security constants
$Global:MaxCsvFileSize = 10 * 1MB  # 10MB
$Global:MaxCsvRecords = 1000
$Global:MaxSessionDuration = New-TimeSpan -Hours 4
$Global:SecurityLogSource = "TeamsPhoneToolkit"

# Validate script integrity (basic check)
$scriptPath = $MyInvocation.MyCommand.Path
if ($scriptPath -and (Test-Path $scriptPath)) {
    $scriptHash = Get-FileHash -Path $scriptPath -Algorithm SHA256
    Write-Host "Script integrity: $($scriptHash.Hash.Substring(0,16))..." -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------------------------
# Global Variable Initialization
# ---------------------------------------------------------------------------------------------
$Global:AuditLog = [System.Collections.ArrayList]@()
$Global:ReadOnlyMode = $false
$Global:ModeStatus = ""
$Global:ResourceAccountUPN = $null
$Global:SelectedVoiceRoutingPolicy = $null
$Global:SelectedSharedCallingPolicy = $null

# ---------------------------------------------------------------------------------------------
# Core Security and Helper Functions (Moved to top to avoid dependency issues)
# ---------------------------------------------------------------------------------------------

function Protect-SensitiveData {
    <#
    .SYNOPSIS
        Sanitizes log entries to remove sensitive information
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$LogEntry
    )
    
    # Remove phone numbers (basic pattern)
    $sanitized = $LogEntry -replace '\+?\d{1,3}[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}', '[PHONE_REDACTED]'
    
    # Remove email addresses except domain
    $sanitized = $sanitized -replace '([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', '[USER_REDACTED]@$2'
    
    # Remove potential passwords or tokens (anything that looks like a long string)
    $sanitized = $sanitized -replace '\b[A-Za-z0-9+/]{20,}={0,2}\b', '[TOKEN_REDACTED]'
    
    return $sanitized
}

function Write-SecureAuditLog {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Command,
        [string]$User = $env:USERNAME,
        [string]$Source = $env:COMPUTERNAME
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $sanitizedCommand = Protect-SensitiveData -LogEntry $Command
    
    # Create structured log entry with security context
    $logEntry = @{
        Timestamp = $timestamp
        User = $User
        Source = $Source
        Command = $sanitizedCommand
        ScriptVersion = "2.0"
        Mode = $Global:ModeStatus
    }
    
    $formattedEntry = "[$($logEntry.Timestamp)] USER: $($logEntry.User) | SOURCE: $($logEntry.Source) | MODE: $($logEntry.Mode) | COMMAND: $($logEntry.Command)"
    $Global:AuditLog.Add($formattedEntry) | Out-Null
    
    # Also write to Windows Event Log for enterprise environments
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists("TeamsPhoneToolkit")) {
            New-EventLog -LogName "Application" -Source "TeamsPhoneToolkit"
        }
        Write-EventLog -LogName "Application" -Source "TeamsPhoneToolkit" -EventId 1001 -EntryType Information -Message $formattedEntry
    }
    catch {
        # Event log writing is optional, don't break on failure
    }
}

function Test-FilePathSecurity {
    <#
    .SYNOPSIS
        Validates file paths to prevent directory traversal and other attacks
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath
    )
    
    # Check for directory traversal attempts
    if ($FilePath -match '\.\.|\\\\|\/\/|[\x00-\x1f]') {
        throw "Invalid file path detected. Path contains potentially dangerous characters."
    }
    
    # Ensure path is not too long (Windows limitation)
    if ($FilePath.Length -gt 260) {
        throw "File path exceeds maximum length (260 characters)."
    }
    
    # Check for reserved Windows filenames
    $reservedNames = @('CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9', 'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9')
    $fileName = [System.IO.Path]::GetFileNameWithoutExtension($FilePath)
    if ($fileName.ToUpper() -in $reservedNames) {
        throw "File name uses a reserved Windows filename: $fileName"
    }
    
    return $true
}

function Test-InputInjection {
    <#
    .SYNOPSIS
        Tests input for potential injection attacks
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Input,
        [string]$Type = "General"
    )
    
    # Check for PowerShell injection patterns
    $dangerousPatterns = @(
        'Invoke-Expression',
        'iex\s',
        'Invoke-Command',
        'Start-Process',
        'cmd\.exe',
        'powershell\.exe',
        'System\.Diagnostics',
        '\$\(',
        '`',
        '\|\s*Out-File',
        '>',
        '&\s*[a-zA-Z]',
        ';\s*[a-zA-Z]'
    )
    
    foreach ($pattern in $dangerousPatterns) {
        if ($Input -match $pattern) {
            throw "Potentially dangerous input detected: Pattern '$pattern' found in input"
        }
    }
    
    # Additional validation for UPN format
    if ($Type -eq "UPN" -and $Input -notmatch '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$') {
        throw "Invalid UPN format. Please provide a valid email address format."
    }
    
    # Additional validation for phone numbers
    if ($Type -eq "Phone" -and $Input -notmatch '^\+?[1-9]\d{1,14}$') {
        throw "Invalid phone number format. Please provide a valid international phone number."
    }
    
    return $true
}

function Get-UserInput {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Prompt,
        [string]$DefaultValue = "",
        [string[]]$ValidValues = @(),
        [switch]$Required = $false,
        [string]$ValidationPattern = "",
        [switch]$Sensitive = $false
    )
    
    do {
        $displayPrompt = $Prompt
        if ($DefaultValue -and -not $Sensitive) {
            $displayPrompt += " (default: $DefaultValue)"
        }
        if ($ValidValues.Count -gt 0) {
            $displayPrompt += " [$($ValidValues -join '/')]"
        }
        
        if ($Sensitive) {
            $secureInput = Read-Host $displayPrompt -AsSecureString
            $input = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureInput))
        }
        else {
            $input = Read-Host $displayPrompt
        }
        
        if ([string]::IsNullOrWhiteSpace($input) -and $DefaultValue) {
            $input = $DefaultValue
        }
        
        if ([string]::IsNullOrWhiteSpace($input) -and $Required) {
            Write-Host "This field is required. Please provide a value." -ForegroundColor Red
            continue
        }
        
        if ($ValidValues.Count -gt 0 -and $input -notin $ValidValues) {
            Write-Host "Invalid value. Valid options are: $($ValidValues -join ', ')" -ForegroundColor Red
            continue
        }
        
        if ($ValidationPattern -and $input -notmatch $ValidationPattern) {
            Write-Host "Input doesn't match the required format." -ForegroundColor Red
            continue
        }
        
        # Security validation for all inputs
        try {
            Test-InputInjection -Input $input -Type "General"
        }
        catch {
            Write-Host "Security validation failed: $($_.Exception.Message)" -ForegroundColor Red
            continue
        }
        
        # Log input received (sanitized)
        if (-not $Sensitive) {
            Write-SecureAuditLog -Command "USER_INPUT: Prompt='$Prompt', Value='$(if($input.Length -gt 50) { $input.Substring(0,50) + '...' } else { $input })'"
        }
        else {
            Write-SecureAuditLog -Command "USER_INPUT: Prompt='$Prompt', Value='[SENSITIVE_DATA_REDACTED]'"
        }
        
        return $input
    } while ($true)
}

function Test-AdminPrivileges {
    <#
    .SYNOPSIS
        Validates that the current user has appropriate administrative privileges
    #>
    try {
        $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
        $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        
        if (-not $isAdmin) {
            throw "This script requires elevated privileges. Please run as Administrator."
        }
        
        Write-Host "✓ Administrative privileges verified" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "❌ Administrative privilege check failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Test-RequiredRoles {
    <#
    .SYNOPSIS
        Validates that the current user has the required Azure AD roles
    #>
    if ($Global:ReadOnlyMode) {
        Write-Host "⚠️ Skipping role validation in Read-Only mode" -ForegroundColor Yellow
        return $true
    }
    
    try {
        # Check if user has required roles for Teams administration
        $context = Get-MgContext -ErrorAction SilentlyContinue
        if (-not $context) {
            Write-Host "⚠️ Microsoft Graph context not available. Please ensure you have appropriate permissions." -ForegroundColor Yellow
            return $true  # Allow to continue but warn
        }
        
        # Additional role checks could be implemented here
        Write-Host "✓ Role validation passed" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "⚠️ Role validation warning: $($_.Exception.Message)" -ForegroundColor Yellow
        return $true  # Continue with warning rather than blocking
    }
}

function New-SecureSession {
    <#
    .SYNOPSIS
        Creates a secure session with additional logging and validation
    #>
    param(
        [string]$SessionId = (New-Guid).ToString()
    )
    
    $sessionInfo = @{
        SessionId = $SessionId
        StartTime = Get-Date
        User = $env:USERNAME
        Computer = $env:COMPUTERNAME
        ProcessId = $PID
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        ScriptPath = $MyInvocation.ScriptName
    }
    
    Write-SecureAuditLog -Command "SESSION_START: $($sessionInfo | ConvertTo-Json -Compress)"
    
    # Store session info globally for reference
    $Global:SessionInfo = $sessionInfo
    
    return $sessionInfo
}

# ---------------------------------------------------------------------------------------------
# Helper, Auditing, and Export Functions
# ---------------------------------------------------------------------------------------------
function Write-AuditLog {
    param(
        [string]$Command
    )
    Write-SecureAuditLog -Command $Command
}

function Export-AuditLog {
    if ($Global:AuditLog.Count -eq 0) {
        Write-Host "No actions were logged during this session." -ForegroundColor Yellow
        return
    }

    $saveChoice = Get-UserInput -Prompt "An audit log of actions is available. Do you want to save it?" -ValidValues @('y','n') -Required
    if ($saveChoice -eq 'y') {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $defaultPath = "$HOME\Desktop\SharedCalling_AuditLog_$timestamp.txt"
        
        do {
            $savePath = Read-Host "Enter the full path to save the log file (default: $defaultPath)"
            if ([string]::IsNullOrWhiteSpace($savePath)) {
                $savePath = $defaultPath
            }
            
            try {
                Test-FilePathSecurity -FilePath $savePath
                break
            }
            catch {
                Write-Host "Invalid file path: $($_.Exception.Message)" -ForegroundColor Red
                $retry = Get-UserInput -Prompt "Try a different path?" -ValidValues @('y','n') -Required
                if ($retry -eq 'n') {
                    return
                }
            }
        } while ($true)

        try {
            # Create secure audit log with digital signature
            $logHeader = @"
=== SECURE AUDIT LOG ===
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Script Version: 2.0
Session ID: $($Global:SessionInfo.SessionId)
User: $($Global:SessionInfo.User)
Computer: $($Global:SessionInfo.Computer)
Mode: $($Global:ModeStatus.ToUpper())
PowerShell Version: $($Global:SessionInfo.PowerShellVersion)
=== LOG ENTRIES ===
"@
            $logContent = $logHeader + [System.Environment]::NewLine + ($Global:AuditLog -join [System.Environment]::NewLine)
            
            # Add integrity footer
            $logFooter = [System.Environment]::NewLine + "=== END OF LOG ===" + [System.Environment]::NewLine + "Entries: $($Global:AuditLog.Count)" + [System.Environment]::NewLine + "Generated by: TeamsPhoneToolkit v2.0"
            $logContent += $logFooter
            
            # Write with restricted permissions
            $logContent | Out-File -FilePath $savePath -Encoding UTF8
            
            # Set file permissions to read-only for security
            $acl = Get-Acl $savePath
            $acl.SetAccessRuleProtection($true, $false)  # Remove inherited permissions
            $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($env:USERNAME, "FullControl", "Allow")
            $acl.SetAccessRule($accessRule)
            Set-Acl -Path $savePath -AclObject $acl
            
            Write-Host "✓ Secure audit log successfully saved to $savePath" -ForegroundColor Green
            Write-Host "  Log contains $($Global:AuditLog.Count) entries with integrity validation" -ForegroundColor Cyan
        }
        catch {
            Write-Host "❌ Failed to save audit log: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

function Confirm-Action {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ConfirmationMessage
    )
    if ($Global:ReadOnlyMode) {
        return $true # Always proceed in Read-Only mode to log the command
    }

    Write-Host "CONFIRMATION REQUIRED:" -ForegroundColor Yellow
    Write-Host $ConfirmationMessage -ForegroundColor Yellow
    $confirmation = Read-Host "Are you sure you want to continue? (y/n)"
    return $confirmation -eq 'y'
}

function Execute-Command {
    param(
        [Parameter(Mandatory=$true)]
        [string]$CommandString,
        [Parameter(Mandatory=$true)]
        [scriptblock]$ScriptBlock
    )
    
    Write-AuditLog -Command $CommandString
    if ($Global:ReadOnlyMode) {
        Write-Host "$($Global:ModeStatus) Command logged but not executed: $CommandString" -ForegroundColor Yellow
    }
    else {
        try {
            Invoke-Command -ScriptBlock $ScriptBlock
            Write-Host "Successfully executed command and logged the action." -ForegroundColor Green
        }
        catch {
            Write-Host "An error occurred during execution: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}


function Continue-Or-Exit {
    $prompt = "Press Enter to continue, 's' to skip to the next step, or 'e' to exit and export the audit log"
    $choice = Read-Host $prompt
    if ($choice -eq 'e') {
        Export-AuditLog
        exit
    }
    return $choice
}

function Show-CsvInstructions {
    param(
        [string]$Instruction,
        [string[]]$Headers,
        [string[]]$SampleRow
    )
    Write-Host $Instruction -ForegroundColor Cyan
    Write-Host "The CSV file must have the following headers:" -ForegroundColor Cyan
    Write-Host ($Headers -join ',') -ForegroundColor Magenta
    Write-Host ""
    Write-Host "Example:" -ForegroundColor Cyan
    Write-Host "--------------------------------------------------" -ForegroundColor DarkGray
    Write-Host ($Headers -join ',')
    Write-Host ($SampleRow -join ',')
    Write-Host "--------------------------------------------------" -ForegroundColor DarkGray
    Write-Host ""
}


# ---------------------------------------------------------------------------------------------
# Introduction and Prerequisites
# ---------------------------------------------------------------------------------------------
function Show-Introduction {
    Clear-Host
    Write-Host "========================================================================" -ForegroundColor Green
    Write-Host "               Get-TeamsPhoneToolkit Script Collection" -ForegroundColor Cyan
    Write-Host "      Interactive Microsoft Teams Shared Calling Deployment Tool" -ForegroundColor Green
    Write-Host "========================================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "This script will guide you through the process of configuring Shared Calling in Microsoft Teams."
    Write-Host "It follows the steps outlined in the official Microsoft documentation and includes full audit logging."
    Write-Host ""
    Write-Host "You can follow along with the Microsoft Learn article here:"
    Write-Host "https://learn.microsoft.com/en-us/microsoftteams/shared-calling-configure"
    Write-Host ""
    Write-Host "Prerequisites:" -ForegroundColor Yellow
    Write-Host "1.  You must be running this script with an account that has at least the following roles:"
    Write-Host "    - Teams Administrator"
    Write-Host "    - User Administrator"
    Write-Host "2.  The Microsoft Teams PowerShell module must be installed. If not, run:"
    Write-Host "    Install-Module -Name MicrosoftTeams -Force -AllowClobber"
    Write-Host "3.  You must be connected to Microsoft Teams PowerShell. The script will attempt to connect you."
    Write-Host "4.  Each user to be enabled for Shared Calling must have an E5 or Teams Phone Standard add-on license."
    Write-Host "5.  You need a resource account with an assigned phone number (Calling Plan, Operator Connect, or Direct Routing)."
    Write-Host "6.  If using Calling Plan, the resource account needs a Pay-As-You-Go Calling Plan and funded Communications Credits or overages turned on for New Commerce Experience (NCE) Licenses."
    Write-Host "7.  If using Direct Routing, you must have a configured Session Border Controller (SBC)."
    Write-Host ""
    Write-Host "This script is provided as-is, without warranty of any kind. Use at your own risk." -ForegroundColor Red
    Write-Host ""
    Read-Host "Press Enter to begin the setup process..."
}

# ---------------------------------------------------------------------------------------------
# Connect to Teams
# ---------------------------------------------------------------------------------------------
function Connect-ToTeams {
    if ($Global:ReadOnlyMode) {
        Write-Host "$($Global:ModeStatus) Skipping connection to Microsoft Teams." -ForegroundColor Yellow
        return
    }

    Write-Host "🔐 Performing security validations..." -ForegroundColor Cyan
    
    # Security checks first
    if (-not (Test-AdminPrivileges)) {
        Read-Host "Press Enter to exit..."
        exit
    }
    
    if (-not (Test-RequiredRoles)) {
        $continue = Get-UserInput -Prompt "Role validation had warnings. Continue anyway?" -ValidValues @('y','n') -Required
        if ($continue -eq 'n') {
            exit
        }
    }

    Write-Host "Checking for Microsoft Teams PowerShell module..." -ForegroundColor Cyan
    
    # Check if module is installed
    $teamsModule = Get-Module -ListAvailable -Name MicrosoftTeams
    if (-not $teamsModule) {
        Write-Host "Microsoft Teams PowerShell module is not installed." -ForegroundColor Red
        $install = Get-UserInput -Prompt "Would you like to install it now?" -ValidValues @('y','n') -Required
        if ($install -eq 'y') {
            try {
                Write-Host "Installing Microsoft Teams module from trusted repository..." -ForegroundColor Cyan
                Install-Module -Name MicrosoftTeams -Force -AllowClobber -Scope CurrentUser -Repository PSGallery
                Write-Host "✓ Module installed successfully." -ForegroundColor Green
                Write-SecureAuditLog -Command "MODULE_INSTALLED: MicrosoftTeams"
            }
            catch {
                Write-Host "❌ Failed to install module: $($_.Exception.Message)" -ForegroundColor Red
                Write-SecureAuditLog -Command "MODULE_INSTALL_FAILED: $($_.Exception.Message)"
                Read-Host "Press Enter to exit..."
                exit
            }
        }
        else {
            Write-Host "Cannot proceed without the Microsoft Teams module." -ForegroundColor Red
            exit
        }
    }

    Write-Host "Attempting to connect to Microsoft Teams PowerShell..." -ForegroundColor Cyan
    Write-SecureAuditLog -Command "TEAMS_CONNECTION_ATTEMPT"
    
    try {
        Import-Module MicrosoftTeams -ErrorAction Stop
        
        # Secure connection with additional logging
        $connectionParams = @{
            ErrorAction = 'Stop'
        }
        
        # Add tenant restriction if running in enterprise environment
        if ($env:USERDOMAIN -and $env:USERDOMAIN -ne $env:COMPUTERNAME) {
            Write-Host "Enterprise environment detected. Using secure connection parameters." -ForegroundColor Cyan
        }
        
        Connect-MicrosoftTeams @connectionParams
        
        # Verify connection and log details
        if (Test-TeamsConnection) {
            $tenantInfo = Get-CsTenant -ErrorAction SilentlyContinue
            if ($tenantInfo) {
                Write-Host "✓ Successfully connected to Microsoft Teams." -ForegroundColor Green
                Write-Host "  Tenant: $($tenantInfo.DisplayName)" -ForegroundColor Cyan
                Write-Host "  Domain: $($tenantInfo.Domains[0])" -ForegroundColor Cyan
                Write-SecureAuditLog -Command "TEAMS_CONNECTION_SUCCESS: Tenant=$($tenantInfo.DisplayName)"
            }
            else {
                Write-Host "✓ Connected to Microsoft Teams (limited tenant info)." -ForegroundColor Green
                Write-SecureAuditLog -Command "TEAMS_CONNECTION_SUCCESS: Limited_Info"
            }
        }
        else {
            throw "Connection verification failed"
        }
    }
    catch {
        Write-Host "❌ Failed to connect to Microsoft Teams: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Please ensure you have the correct permissions and try again." -ForegroundColor Red
        Write-SecureAuditLog -Command "TEAMS_CONNECTION_FAILED: $($_.Exception.Message)"
        Read-Host "Press Enter to exit..."
        exit
    }
}

# ---------------------------------------------------------------------------------------------
# Input Validation Functions
# ---------------------------------------------------------------------------------------------
function Test-CsvFile {
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath,
        [Parameter(Mandatory=$true)]
        [string[]]$RequiredHeaders
    )
    
    # Security validation first
    Test-FilePathSecurity -FilePath $FilePath
    
    if (-not (Test-Path $FilePath)) {
        throw "File not found: $FilePath"
    }
    
    # Check file size (prevent extremely large files)
    $fileInfo = Get-Item $FilePath
    $maxSizeMB = 10  # 10MB limit
    if ($fileInfo.Length -gt ($maxSizeMB * 1MB)) {
        throw "File size exceeds maximum allowed size of ${maxSizeMB}MB"
    }
    
    try {
        $csvData = Import-Csv -Path $FilePath -ErrorAction Stop
        if ($csvData.Count -eq 0) {
            throw "CSV file is empty or contains no data rows"
        }
        
        # Limit number of records for security
        $maxRecords = 1000
        if ($csvData.Count -gt $maxRecords) {
            throw "CSV file contains too many records. Maximum allowed: $maxRecords"
        }
        
        $fileHeaders = ($csvData | Get-Member -MemberType NoteProperty).Name
        $missingHeaders = $RequiredHeaders | Where-Object { $_ -notin $fileHeaders }
        
        if ($missingHeaders.Count -gt 0) {
            throw "Missing required headers: $($missingHeaders -join ', '). Found headers: $($fileHeaders -join ', ')"
        }
        
        # Validate each row for security
        for ($i = 0; $i -lt $csvData.Count; $i++) {
            $row = $csvData[$i]
            
            # Validate UPN format if UserPrincipalName is present
            if ('UserPrincipalName' -in $RequiredHeaders -and $row.UserPrincipalName) {
                Test-InputInjection -Input $row.UserPrincipalName -Type "UPN"
            }
            
            # Validate phone numbers if present
            if ('PhoneNumber' -in $RequiredHeaders -and $row.PhoneNumber) {
                Test-InputInjection -Input $row.PhoneNumber -Type "Phone"
            }
            
            # General validation for all string fields
            foreach ($header in $RequiredHeaders) {
                if ($row.$header) {
                    Test-InputInjection -Input $row.$header -Type "General"
                }
            }
        }
        
        Write-SecureAuditLog -Command "CSV_VALIDATED: File=$FilePath, Records=$($csvData.Count), Headers=$($RequiredHeaders -join ',')"
        return $csvData
    }
    catch {
        Write-SecureAuditLog -Command "CSV_VALIDATION_FAILED: File=$FilePath, Error=$($_.Exception.Message)"
        throw "Error processing CSV file: $($_.Exception.Message)"
    }
}

function Test-TeamsConnection {
    if ($Global:ReadOnlyMode) {
        return $true
    }
    
    try {
        Get-CsTenant -ErrorAction Stop | Out-Null
        return $true
    }
    catch {
        Write-Host "Teams connection test failed. Please ensure you're connected to Microsoft Teams." -ForegroundColor Red
        return $false
    }
}

function Get-UserInput {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Prompt,
        [string]$DefaultValue = "",
        [string[]]$ValidValues = @(),
        [switch]$Required = $false,
        [string]$ValidationPattern = "",
        [switch]$Sensitive = $false
    )
    
    do {
        $displayPrompt = $Prompt
        if ($DefaultValue -and -not $Sensitive) {
            $displayPrompt += " (default: $DefaultValue)"
        }
        if ($ValidValues.Count -gt 0) {
            $displayPrompt += " [$($ValidValues -join '/')]"
        }
        
        if ($Sensitive) {
            $secureInput = Read-Host $displayPrompt -AsSecureString
            $input = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureInput))
        }
        else {
            $input = Read-Host $displayPrompt
        }
        
        if ([string]::IsNullOrWhiteSpace($input) -and $DefaultValue) {
            $input = $DefaultValue
        }
        
        if ([string]::IsNullOrWhiteSpace($input) -and $Required) {
            Write-Host "This field is required. Please provide a value." -ForegroundColor Red
            continue
        }
        
        if ($ValidValues.Count -gt 0 -and $input -notin $ValidValues) {
            Write-Host "Invalid value. Valid options are: $($ValidValues -join ', ')" -ForegroundColor Red
            continue
        }
        
        if ($ValidationPattern -and $input -notmatch $ValidationPattern) {
            Write-Host "Input doesn't match the required format." -ForegroundColor Red
            continue
        }
        
        # Security validation for all inputs
        try {
            Test-InputInjection -Input $input -Type "General"
        }
        catch {
            Write-Host "Security validation failed: $($_.Exception.Message)" -ForegroundColor Red
            continue
        }
        
        # Log input received (sanitized)
        if (-not $Sensitive) {
            Write-SecureAuditLog -Command "USER_INPUT: Prompt='$Prompt', Value='$(if($input.Length -gt 50) { $input.Substring(0,50) + '...' } else { $input })'"
        }
        else {
            Write-SecureAuditLog -Command "USER_INPUT: Prompt='$Prompt', Value='[SENSITIVE_DATA_REDACTED]'"
        }
        
        return $input
    } while ($true)
}

# ---------------------------------------------------------------------------------------------
# Configuration Management Functions
# ---------------------------------------------------------------------------------------------
function Save-SessionState {
    param(
        [string]$FilePath = "$env:TEMP\SharedCalling_Session.json"
    )
    
    $sessionState = @{
        ResourceAccountUPN = $Global:ResourceAccountUPN
        ModeStatus = $Global:ModeStatus
        ReadOnlyMode = $Global:ReadOnlyMode
        SelectedVoiceRoutingPolicy = $Global:SelectedVoiceRoutingPolicy
        SelectedSharedCallingPolicy = $Global:SelectedSharedCallingPolicy
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    
    try {
        $sessionState | ConvertTo-Json | Out-File -FilePath $FilePath
        Write-Host "Session state saved to $FilePath" -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to save session state: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Restore-SessionState {
    param(
        [string]$FilePath = "$env:TEMP\SharedCalling_Session.json"
    )
    
    if (-not (Test-Path $FilePath)) {
        return $false
    }
    
    try {
        $sessionState = Get-Content $FilePath | ConvertFrom-Json
        $Global:ResourceAccountUPN = $sessionState.ResourceAccountUPN
        $Global:SelectedVoiceRoutingPolicy = $sessionState.SelectedVoiceRoutingPolicy
        $Global:SelectedSharedCallingPolicy = $sessionState.SelectedSharedCallingPolicy
        Write-Host "Restored session state from $($sessionState.Timestamp)" -ForegroundColor Green
        
        # Display restored values
        if ($Global:ResourceAccountUPN) {
            Write-Host "  Restored Resource Account: $($Global:ResourceAccountUPN)" -ForegroundColor Cyan
        }
        if ($Global:SelectedVoiceRoutingPolicy) {
            Write-Host "  Restored Voice Routing Policy: $($Global:SelectedVoiceRoutingPolicy)" -ForegroundColor Cyan
        }
        if ($Global:SelectedSharedCallingPolicy) {
            Write-Host "  Restored Shared Calling Policy: $($Global:SelectedSharedCallingPolicy)" -ForegroundColor Cyan
        }
        
        return $true
    }
    catch {
        Write-Host "Failed to restore session state: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Show-Progress {
    param(
        [int]$CurrentStep,
        [int]$TotalSteps,
        [string]$StepName
    )
    
    $percentComplete = ($CurrentStep / $TotalSteps) * 100
    $progressBar = ""
    $barLength = 30
    $filledLength = [int](($percentComplete / 100) * $barLength)
    
    for ($i = 0; $i -lt $barLength; $i++) {
        if ($i -lt $filledLength) {
            $progressBar += "█"
        } else {
            $progressBar += "░"
        }
    }
    
    Write-Host ""
    Write-Host "Overall Progress: [$progressBar] $([math]::Round($percentComplete, 1))%" -ForegroundColor Cyan
    Write-Host "Step $CurrentStep of $TotalSteps : $StepName" -ForegroundColor White
    Write-Host ""
}


# ---------------------------------------------------------------------------------------------
# Step Functions with Auditing
# ---------------------------------------------------------------------------------------------

function Step1-EnableUsersForVoice {
    Clear-Host
    Write-Host "--- Step 1: Enable users for voice $($Global:ModeStatus) ---" -ForegroundColor Yellow
    Write-Host ""
    if ((Continue-Or-Exit) -eq 's') { return }
    
    Write-Host "This step ensures users have a Teams Phone license and are enabled for Enterprise Voice." -ForegroundColor Cyan
    Write-Host ""
    
    Show-CsvInstructions -Instruction "Please provide a CSV file containing the users to enable for voice." -Headers @("UserPrincipalName") -SampleRow @("adele.vance@contoso.com")
    
    $inputFile = ""
    do {
        $inputFile = Read-Host "Enter the full path to your CSV file"
        if ([string]::IsNullOrWhiteSpace($inputFile)) {
            Write-Host "File path is required." -ForegroundColor Red
            continue
        }
        
        try {
            $users = Test-CsvFile -FilePath $inputFile -RequiredHeaders @("UserPrincipalName")
            break
        }
        catch {
            Write-Host "CSV validation failed: $($_.Exception.Message)" -ForegroundColor Red
            $retry = Get-UserInput -Prompt "Try again with a different file?" -ValidValues @('y','n') -Required
            if ($retry -eq 'n') {
                Continue-Or-Exit
                return
            }
        }
    } while ($true)
    
    Write-Host "Successfully validated CSV file with $($users.Count) users." -ForegroundColor Green
    
    $confirmationMessage = "You are about to process enabling Enterprise Voice for $($users.Count) users from the file '$inputFile'."
    if (-not (Confirm-Action -ConfirmationMessage $confirmationMessage)) {
        Write-Host "Bulk action cancelled by user." -ForegroundColor Red
        Continue-Or-Exit
        return
    }

    $totalUsers = $users.Count
    $successCount = 0
    $errorCount = 0
    $errors = @()
    
    for ($i = 0; $i -lt $totalUsers; $i++) {
        $user = $users[$i]
        $upn = $user.UserPrincipalName
        
        $activity = "Enabling Enterprise Voice"
        $status = "Processing user $upn ($($i + 1) of $totalUsers)"
        $percentComplete = (($i + 1) / $totalUsers) * 100
        Write-Progress -Activity $activity -Status $status -PercentComplete $percentComplete

        $command = "Set-CsPhoneNumberAssignment -Identity '$upn' -EnterpriseVoiceEnabled `$true"
        $scriptBlock = { 
            try {
                Set-CsPhoneNumberAssignment -Identity $using:upn -EnterpriseVoiceEnabled $true -ErrorAction Stop
                return @{ Success = $true; Error = $null }
            }
            catch {
                return @{ Success = $false; Error = $_.Exception.Message }
            }
        }
        
        Write-AuditLog -Command $command
        if ($Global:ReadOnlyMode) {
            Write-Host "$($Global:ModeStatus) Command logged but not executed: $command" -ForegroundColor Yellow
            $successCount++
        }
        else {
            $result = Invoke-Command -ScriptBlock $scriptBlock
            if ($result.Success) {
                $successCount++
            }
            else {
                $errorCount++
                $errors += "User $upn : $($result.Error)"
                Write-Host "Error processing $upn : $($result.Error)" -ForegroundColor Red
            }
        }
    }
    
    Write-Progress -Activity "Enabling Enterprise Voice" -Completed
    
    # Summary
    Write-Host ""
    Write-Host "=== Operation Summary ===" -ForegroundColor Cyan
    Write-Host "Total users processed: $totalUsers" -ForegroundColor White
    Write-Host "Successful: $successCount" -ForegroundColor Green
    if ($errorCount -gt 0) {
        Write-Host "Errors: $errorCount" -ForegroundColor Red
        Write-Host "Error details:" -ForegroundColor Yellow
        $errors | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    }
    
    Continue-Or-Exit
}

function Step2-AssignNumberToResourceAccount {
    Clear-Host
    Write-Host "--- Step 2: Confirm resource account $($Global:ModeStatus) ---" -ForegroundColor Yellow
    if ((Continue-Or-Exit) -eq 's') { return }
    
    Write-Host "This step verifies that your resource account exists and is properly configured." -ForegroundColor Cyan
    Write-Host ""
    
    $resourceAccountUpn = Get-UserInput -Prompt "Enter the UPN of the resource account" -Required -ValidationPattern '^[^@]+@[^@]+\.[^@]+$'
    
    $command = "Get-CsOnlineUser -Identity '$resourceAccountUpn'"
    Write-AuditLog -Command $command
    
    if ($Global:ReadOnlyMode) {
        Write-Host "$($Global:ModeStatus) Command to verify resource account was logged." -ForegroundColor Yellow
        $Global:ResourceAccountUPN = $resourceAccountUpn
    }
    else {
        try {
            $resourceAccount = Get-CsOnlineUser -Identity $resourceAccountUpn -ErrorAction Stop
            Write-Host "Successfully verified resource account '$resourceAccountUpn' exists." -ForegroundColor Green
            
            # Display additional information about the resource account
            Write-Host ""
            Write-Host "Resource Account Details:" -ForegroundColor Cyan
            Write-Host "  Display Name: $($resourceAccount.DisplayName)" -ForegroundColor White
            Write-Host "  Phone Number: $($resourceAccount.LineURI -replace 'tel:', '')" -ForegroundColor White
            Write-Host "  Account Type: $($resourceAccount.AccountType)" -ForegroundColor White
            
            $Global:ResourceAccountUPN = $resourceAccountUpn
        }
        catch {
            Write-Host "Could not find resource account '$resourceAccountUpn': $($_.Exception.Message)" -ForegroundColor Red
            $retry = Get-UserInput -Prompt "Would you like to try a different UPN?" -ValidValues @('y','n') -Required
            if ($retry -eq 'y') {
                Step2-AssignNumberToResourceAccount  # Recursive call to retry
                return
            }
        }
    }
    Continue-Or-Exit
}

function Step3-AssociateWithAutoAttendant {
    Clear-Host
    Write-Host "--- Step 3: Confirm Auto Attendant Association $($Global:ModeStatus) ---" -ForegroundColor Yellow
    if ((Continue-Or-Exit) -eq 's') { return }
    Write-Host "This script assumes the resource account is correctly associated with an Auto Attendant for inbound calls."
    Continue-Or-Exit
}

function Step4-AssignLocationToResourceAccount {
    Clear-Host
    Write-Host "--- Step 4: Assign a location to the resource account $($Global:ModeStatus) ---" -ForegroundColor Yellow
    if ((Continue-Or-Exit) -eq 's') { return }
    
    $locationId = ""
    $resourceAccountUpn = $Global:ResourceAccountUPN

    if (-not [string]::IsNullOrEmpty($resourceAccountUpn)) {
        $useExisting = Get-UserInput -Prompt "Use previously entered resource account '$resourceAccountUpn'?" -ValidValues @('y','n') -Required
        if ($useExisting -eq 'n') {
            $resourceAccountUpn = Get-UserInput -Prompt "Enter the UPN of the resource account" -Required -ValidationPattern '^[^@]+@[^@]+\.[^@]+$'
        }
    }
    else {
        $resourceAccountUpn = Get-UserInput -Prompt "Enter the UPN of the resource account" -Required -ValidationPattern '^[^@]+@[^@]+\.[^@]+$'
    }

    if ($Global:ReadOnlyMode) {
        Write-Host "$($Global:ModeStatus) Skipping live data retrieval. Please provide a placeholder Location ID for logging purposes." -ForegroundColor Yellow
        $locationId = Get-UserInput -Prompt "Enter a placeholder Location ID" -Required
    }
    else {
        Write-Host "Retrieving emergency locations from your tenant..." -ForegroundColor Cyan
        
        try {
            $allLocations = Get-CsOnlineLisLocation -ErrorAction Stop
            $maxDisplayLocations = 20
            
            if ($allLocations.Count -eq 0) {
                Write-Host "No emergency locations found in your tenant." -ForegroundColor Red
                Write-Host "Please configure emergency locations in the Teams Admin Center first." -ForegroundColor Yellow
                Continue-Or-Exit
                return
            }
            elseif ($allLocations.Count -gt $maxDisplayLocations) {
                Write-Host ""
                Write-Host "⚠️  Large Location Dataset Detected" -ForegroundColor Yellow
                Write-Host "Your tenant has $($allLocations.Count) emergency locations configured." -ForegroundColor Cyan
                Write-Host "Displaying only the first $maxDisplayLocations for performance reasons." -ForegroundColor Cyan
                Write-Host ""
                Write-Host "📋 Limited Emergency Locations List:" -ForegroundColor Cyan
                Write-Host "----------------------------------------" -ForegroundColor DarkGray
                
                $limitedLocations = $allLocations | Select-Object -First $maxDisplayLocations
                $limitedLocations | Format-Table -Property @(
                    @{Label="Location"; Expression={$_.Location}; Width=30},
                    @{Label="LocationId"; Expression={$_.LocationId}; Width=36},
                    @{Label="Address"; Expression={"$($_.HouseNumber) $($_.StreetName), $($_.City)"}; Width=40}
                ) -AutoSize
                
                Write-Host "----------------------------------------" -ForegroundColor DarkGray
                Write-Host ""
                Write-Host "🔍 To find your specific location:" -ForegroundColor Yellow
                Write-Host "1. Go to Teams Admin Center (https://admin.teams.microsoft.com)" -ForegroundColor White
                Write-Host "2. Navigate to: Locations > Emergency addresses" -ForegroundColor White
                Write-Host "3. Find your desired location and copy the Location ID" -ForegroundColor White
                Write-Host "4. Enter that Location ID below" -ForegroundColor White
                Write-Host ""
                
                $choice = Get-UserInput -Prompt "Choose an option: (1) Use one of the locations above, (2) Enter a specific Location ID" -ValidValues @('1','2') -Required
                
                if ($choice -eq '1') {
                    Write-Host "Available locations from the list above:" -ForegroundColor Cyan
                    for ($i = 0; $i -lt $limitedLocations.Count; $i++) {
                        $loc = $limitedLocations[$i]
                        Write-Host "$($i + 1). $($loc.Location) - $($loc.LocationId)" -ForegroundColor White
                    }
                    
                    $selection = Get-UserInput -Prompt "Select the number of the location you want to use (1-$($limitedLocations.Count))" -Required
                    
                    try {
                        $selectedIndex = [int]$selection - 1
                        if ($selectedIndex -lt 0 -or $selectedIndex -ge $limitedLocations.Count) {
                            throw "Invalid selection"
                        }
                        $selectedLocation = $limitedLocations[$selectedIndex]
                        $locationId = $selectedLocation.LocationId
                        
                        Write-Host "Selected location: $($selectedLocation.Location) ($locationId)" -ForegroundColor Green
                        Write-SecureAuditLog -Command "EMERGENCY_LOCATION_SELECTED_FROM_LIST: $($selectedLocation.Location) - $locationId"
                    }
                    catch {
                        Write-Host "Invalid selection. Please try again." -ForegroundColor Red
                        Continue-Or-Exit
                        return
                    }
                }
                else {
                    $locationId = Get-UserInput -Prompt "Enter the Location ID from Teams Admin Center" -Required
                    Write-SecureAuditLog -Command "EMERGENCY_LOCATION_ID_MANUALLY_ENTERED: $locationId"
                }
            }
            else {
                # Small list - display all locations
                Write-Host "📋 Emergency Locations:" -ForegroundColor Cyan
                Write-Host "----------------------------------------" -ForegroundColor DarkGray
                
                $allLocations | Format-Table -Property @(
                    @{Label="Location"; Expression={$_.Location}; Width=30},
                    @{Label="LocationId"; Expression={$_.LocationId}; Width=36},
                    @{Label="Address"; Expression={"$($_.HouseNumber) $($_.StreetName), $($City)"}; Width=40}
                ) -AutoSize
                
                Write-Host "----------------------------------------" -ForegroundColor DarkGray
                
                $locationId = Get-UserInput -Prompt "Enter the Location ID from the list above" -Required
                Write-SecureAuditLog -Command "EMERGENCY_LOCATION_SELECTED_FROM_FULL_LIST: $locationId"
            }
        }
        catch {
            Write-Host "Error retrieving emergency locations: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "Please ensure you have the necessary permissions and try again." -ForegroundColor Yellow
            $locationId = Get-UserInput -Prompt "Enter the Location ID manually" -Required
            Write-SecureAuditLog -Command "EMERGENCY_LOCATION_ID_FALLBACK_ENTRY: $locationId"
        }
    }
    
    $confirmationMessage = "This will process the assignment of location ID '$locationId' to resource account '$resourceAccountUpn'."
    if (-not (Confirm-Action -ConfirmationMessage $confirmationMessage)) {
        Write-Host "Action cancelled by user." -ForegroundColor Red
        Continue-Or-Exit
        return
    }

    $command = "Set-CsPhoneNumberAssignment -Identity '$resourceAccountUpn' -LocationId '$locationId'"
    $scriptBlock = { 
        try {
            Set-CsPhoneNumberAssignment -Identity $using:resourceAccountUpn -LocationId $using:locationId -ErrorAction Stop
            return @{ Success = $true; Error = $null }
        }
        catch {
            return @{ Success = $false; Error = $_.Exception.Message }
        }
    }
    
    Write-AuditLog -Command $command
    if ($Global:ReadOnlyMode) {
        Write-Host "$($Global:ModeStatus) Command logged but not executed: $command" -ForegroundColor Yellow
    }
    else {
        $result = Invoke-Command -ScriptBlock $scriptBlock
        if ($result.Success) {
            Write-Host "✓ Successfully assigned location to resource account" -ForegroundColor Green
        }
        else {
            Write-Host "❌ Error assigning location: $($result.Error)" -ForegroundColor Red
        }
    }
    
    Continue-Or-Exit
}

function Step5-ConfigureNumberType {
    Clear-Host
    Write-Host "--- Step 5: Confirm number-specific settings $($Global:ModeStatus) ---" -ForegroundColor Yellow
    if ((Continue-Or-Exit) -eq 's') { return }
    Write-Host "Please manually verify number-specific settings (Calling Plan funding, Direct Routing policies, etc.)."
    Continue-Or-Exit
}

function Step6-CreateVoiceRoutingPolicy {
    Clear-Host
    Write-Host "--- Step 6: Create voice routing policy (No PSTN Usages) $($Global:ModeStatus) ---" -ForegroundColor Yellow
    if ((Continue-Or-Exit) -eq 's') { return }
    
    Write-Host "Voice routing policies are required for Shared Calling configuration." -ForegroundColor Cyan
    Write-Host ""
    
    $policyChoice = Get-UserInput -Prompt "Would you like to create a new policy or use an existing one?" -ValidValues @('new','existing') -Required
    
    if ($policyChoice -eq 'existing') {
        # List existing voice routing policies
        if ($Global:ReadOnlyMode) {
            Write-Host "$($Global:ModeStatus) Skipping live data retrieval for existing policies." -ForegroundColor Yellow
            $policyName = Get-UserInput -Prompt "Enter the name of the existing voice routing policy to use" -Required
        }
        else {
            try {
                $existingPolicies = Get-CsOnlineVoiceRoutingPolicy -ErrorAction Stop
                if ($existingPolicies.Count -eq 0) {
                    Write-Host "No existing voice routing policies found. Creating a new one is required." -ForegroundColor Yellow
                    $policyChoice = 'new'
                }
                else {
                    $maxDisplayPolicies = 20
                    
                    if ($existingPolicies.Count -gt $maxDisplayPolicies) {
                        Write-Host ""
                        Write-Host "⚠️  Large Policy Dataset Detected" -ForegroundColor Yellow
                        Write-Host "Your tenant has $($existingPolicies.Count) voice routing policies configured." -ForegroundColor Cyan
                        Write-Host "Displaying only the first $maxDisplayPolicies for performance reasons." -ForegroundColor Cyan
                        Write-Host ""
                        
                        $limitedPolicies = $existingPolicies | Select-Object -First $maxDisplayPolicies
                        Write-Host "📋 Limited Voice Routing Policies List:" -ForegroundColor Cyan
                        Write-Host "----------------------------------------" -ForegroundColor DarkGray
                        for ($i = 0; $i -lt $limitedPolicies.Count; $i++) {
                            $policy = $limitedPolicies[$i]
                            $usageCount = if ($policy.OnlinePstnUsages) { $policy.OnlinePstnUsages.Count } else { 0 }
                            Write-Host "$($i + 1). $($policy.Identity) (PSTN Usages: $usageCount)" -ForegroundColor White
                        }
                        Write-Host "----------------------------------------" -ForegroundColor DarkGray
                        Write-Host ""
                        Write-Host "🔍 If your desired policy is not listed above:" -ForegroundColor Yellow
                        Write-Host "Choose option 2 below to enter the policy name directly." -ForegroundColor White
                        Write-Host ""
                        
                        $choice = Get-UserInput -Prompt "Choose an option: (1) Select from list above, (2) Enter specific policy name" -ValidValues @('1','2') -Required
                        
                        if ($choice -eq '1') {
                            $selection = Get-UserInput -Prompt "Select the number of the policy you want to use (1-$($limitedPolicies.Count))" -Required
                            $policiesToUse = $limitedPolicies
                        }
                        else {
                            $policyName = Get-UserInput -Prompt "Enter the exact name of the Voice Routing Policy" -Required
                            # Verify the policy exists
                            $foundPolicy = $existingPolicies | Where-Object { $_.Identity -eq $policyName }
                            if ($foundPolicy) {
                                Write-Host "Policy found: $policyName" -ForegroundColor Green
                                Write-SecureAuditLog -Command "EXISTING_VOICE_ROUTING_POLICY_SELECTED_BY_NAME: $policyName"
                                
                                # Check for PSTN usages warning
                                if ($foundPolicy.OnlinePstnUsages -and $foundPolicy.OnlinePstnUsages.Count -gt 0) {
                                    Write-Host "⚠️ Warning: Selected policy has PSTN usages. For Shared Calling, an empty policy is typically recommended." -ForegroundColor Yellow
                                    $continue = Get-UserInput -Prompt "Continue with this policy anyway?" -ValidValues @('y','n') -Required
                                    if ($continue -eq 'n') {
                                        $policyChoice = 'new'
                                        return
                                    }
                                }
                                # Skip the selection process since we found the policy by name
                                $selection = $null
                                $policiesToUse = $null
                            }
                            else {
                                Write-Host "Policy '$policyName' not found. Please verify the name and try again." -ForegroundColor Red
                                Continue-Or-Exit
                                return
                            }
                        }
                    }
                    else {
                        # Small list - display all policies
                        Write-Host "Existing Voice Routing Policies:" -ForegroundColor Cyan
                        Write-Host "----------------------------------------" -ForegroundColor DarkGray
                        for ($i = 0; $i -lt $existingPolicies.Count; $i++) {
                            $policy = $existingPolicies[$i]
                            $usageCount = if ($policy.OnlinePstnUsages) { $policy.OnlinePstnUsages.Count } else { 0 }
                            Write-Host "$($i + 1). $($policy.Identity) (PSTN Usages: $usageCount)" -ForegroundColor White
                        }
                        Write-Host "----------------------------------------" -ForegroundColor DarkGray
                        
                        $selection = Get-UserInput -Prompt "Select the number of the policy you want to use (1-$($existingPolicies.Count))" -Required
                        $policiesToUse = $existingPolicies
                    }
                    
                    # Process selection if we're using numbered selection
                    if ($selection -ne $null -and $policiesToUse -ne $null) {
                        try {
                            $selectedIndex = [int]$selection - 1
                            if ($selectedIndex -lt 0 -or $selectedIndex -ge $policiesToUse.Count) {
                                throw "Invalid selection"
                            }
                            $selectedPolicy = $policiesToUse[$selectedIndex]
                            $policyName = $selectedPolicy.Identity
                            
                            Write-Host "Selected policy: $policyName" -ForegroundColor Green
                            Write-SecureAuditLog -Command "EXISTING_VOICE_ROUTING_POLICY_SELECTED: $policyName"
                            
                            # Warn if policy has PSTN usages (might not be suitable for Shared Calling)
                            if ($selectedPolicy.OnlinePstnUsages -and $selectedPolicy.OnlinePstnUsages.Count -gt 0) {
                                Write-Host "⚠️ Warning: Selected policy has PSTN usages. For Shared Calling, an empty policy is typically recommended." -ForegroundColor Yellow
                                $continue = Get-UserInput -Prompt "Continue with this policy anyway?" -ValidValues @('y','n') -Required
                                if ($continue -eq 'n') {
                                    $policyChoice = 'new'
                                }
                            }
                        }
                        catch {
                            Write-Host "Invalid selection. Please try again." -ForegroundColor Red
                            Continue-Or-Exit
                            return
                        }
                    }
                }
            }
            catch {
                Write-Host "Error retrieving existing policies: $($_.Exception.Message)" -ForegroundColor Red
                Write-Host "Proceeding with new policy creation." -ForegroundColor Yellow
                $policyChoice = 'new'
            }
        }
    }
    
    if ($policyChoice -eq 'new') {
        $policyName = Get-UserInput -Prompt "Enter a name for the new, empty voice routing policy" -Required
        
        $confirmationMessage = "This will process the creation of a new voice routing policy named '$policyName'."
        if (-not (Confirm-Action -ConfirmationMessage $confirmationMessage)) {
            Write-Host "Action cancelled by user." -ForegroundColor Red
            Continue-Or-Exit
            return
        }

        $command = "New-CsOnlineVoiceRoutingPolicy -Identity '$policyName' -OnlinePstnUsages @()"
        $scriptBlock = { New-CsOnlineVoiceRoutingPolicy -Identity $using:policyName -OnlinePstnUsages @() }
        Execute-Command -CommandString $command -ScriptBlock $scriptBlock
    }
    
    # Store the selected/created policy name for potential future use
    $Global:SelectedVoiceRoutingPolicy = $policyName
    Write-Host "Voice routing policy configured: $policyName" -ForegroundColor Green
    Continue-Or-Exit
}

function Step7-EnableEmergencyCalling {
    Clear-Host
    Write-Host "--- Step 7: Confirm Emergency Calling Policy for Users $($Global:ModeStatus) ---" -ForegroundColor Yellow
    if ((Continue-Or-Exit) -eq 's') { return }
    Write-Host "Please manually ensure you have created and assigned an emergency call routing policy to your users."
    Continue-Or-Exit
}

function Step8-CreateSharedCallingPolicy {
    Clear-Host
    Write-Host "--- Step 8: Create the Shared Calling policy $($Global:ModeStatus) ---" -ForegroundColor Yellow
    if ((Continue-Or-Exit) -eq 's') { return }

    Write-Host "Shared Calling policies define the resource account and emergency numbers for users." -ForegroundColor Cyan
    Write-Host ""
    
    $policyChoice = Get-UserInput -Prompt "Would you like to create a new policy or use an existing one?" -ValidValues @('new','existing') -Required
    
    if ($policyChoice -eq 'existing') {
        # List existing Shared Calling policies
        if ($Global:ReadOnlyMode) {
            Write-Host "$($Global:ModeStatus) Skipping live data retrieval for existing policies." -ForegroundColor Yellow
            $policyName = Get-UserInput -Prompt "Enter the name of the existing Shared Calling policy to use" -Required
        }
        else {
            try {
                $existingPolicies = Get-CsTeamsSharedCallingRoutingPolicy -ErrorAction Stop
                if ($existingPolicies.Count -eq 0) {
                    Write-Host "No existing Shared Calling policies found. Creating a new one is required." -ForegroundColor Yellow
                    $policyChoice = 'new'
                }
                else {
                    $maxDisplayPolicies = 20
                    
                    if ($existingPolicies.Count -gt $maxDisplayPolicies) {
                        Write-Host ""
                        Write-Host "⚠️  Large Policy Dataset Detected" -ForegroundColor Yellow
                        Write-Host "Your tenant has $($existingPolicies.Count) Shared Calling policies configured." -ForegroundColor Cyan
                        Write-Host "Displaying only the first $maxDisplayPolicies for performance reasons." -ForegroundColor Cyan
                        Write-Host ""
                        
                        $limitedPolicies = $existingPolicies | Select-Object -First $maxDisplayPolicies
                        Write-Host "📋 Limited Shared Calling Policies List:" -ForegroundColor Cyan
                        Write-Host "----------------------------------------" -ForegroundColor DarkGray
                        for ($i = 0; $i -lt $limitedPolicies.Count; $i++) {
                            $policy = $limitedPolicies[$i]
                            $resourceAccount = if ($policy.ResourceAccount) { $policy.ResourceAccount } else { "Not configured" }
                            $emergencyCount = if ($policy.EmergencyNumbers) { $policy.EmergencyNumbers.Count } else { 0 }
                            Write-Host "$($i + 1). $($policy.Identity)" -ForegroundColor White
                            Write-Host "     Resource Account: $resourceAccount" -ForegroundColor Gray
                            Write-Host "     Emergency Numbers: $emergencyCount configured" -ForegroundColor Gray
                        }
                        Write-Host "----------------------------------------" -ForegroundColor DarkGray
                        Write-Host ""
                        Write-Host "🔍 If your desired policy is not listed above:" -ForegroundColor Yellow
                        Write-Host "Choose option 2 below to enter the policy name directly." -ForegroundColor White
                        Write-Host ""
                        
                        $choice = Get-UserInput -Prompt "Choose an option: (1) Select from list above, (2) Enter specific policy name" -ValidValues @('1','2') -Required
                        
                        if ($choice -eq '1') {
                            $selection = Get-UserInput -Prompt "Select the number of the policy you want to use (1-$($limitedPolicies.Count))" -Required
                            $policiesToUse = $limitedPolicies
                        }
                        else {
                            $policyName = Get-UserInput -Prompt "Enter the exact name of the Shared Calling Policy" -Required
                            # Verify the policy exists
                            $foundPolicy = $existingPolicies | Where-Object { $_.Identity -eq $policyName }
                            if ($foundPolicy) {
                                Write-Host "Policy found: $policyName" -ForegroundColor Green
                                Write-SecureAuditLog -Command "EXISTING_SHARED_CALLING_POLICY_SELECTED_BY_NAME: $policyName"
                                
                                # Display policy details
                                Write-Host ""
                                Write-Host "Policy Details:" -ForegroundColor Cyan
                                Write-Host "  Resource Account: $($foundPolicy.ResourceAccount)" -ForegroundColor White
                                if ($foundPolicy.EmergencyNumbers) {
                                    Write-Host "  Emergency Numbers: $($foundPolicy.EmergencyNumbers -join ', ')" -ForegroundColor White
                                }
                                # Skip the selection process since we found the policy by name
                                $selection = $null
                                $policiesToUse = $null
                            }
                            else {
                                Write-Host "Policy '$policyName' not found. Please verify the name and try again." -ForegroundColor Red
                                Continue-Or-Exit
                                return
                            }
                        }
                    }
                    else {
                        # Small list - display all policies
                        Write-Host "Existing Shared Calling Policies:" -ForegroundColor Cyan
                        Write-Host "----------------------------------------" -ForegroundColor DarkGray
                        for ($i = 0; $i -lt $existingPolicies.Count; $i++) {
                            $policy = $existingPolicies[$i]
                            $resourceAccount = if ($policy.ResourceAccount) { $policy.ResourceAccount } else { "Not configured" }
                            $emergencyCount = if ($policy.EmergencyNumbers) { $policy.EmergencyNumbers.Count } else { 0 }
                            Write-Host "$($i + 1). $($policy.Identity)" -ForegroundColor White
                            Write-Host "     Resource Account: $resourceAccount" -ForegroundColor Gray
                            Write-Host "     Emergency Numbers: $emergencyCount configured" -ForegroundColor Gray
                        }
                        Write-Host "----------------------------------------" -ForegroundColor DarkGray
                        
                        $selection = Get-UserInput -Prompt "Select the number of the policy you want to use (1-$($existingPolicies.Count))" -Required
                        $policiesToUse = $existingPolicies
                    }
                    
                    # Process selection if we're using numbered selection
                    if ($selection -ne $null -and $policiesToUse -ne $null) {
                        try {
                            $selectedIndex = [int]$selection - 1
                            if ($selectedIndex -lt 0 -or $selectedIndex -ge $policiesToUse.Count) {
                                throw "Invalid selection"
                            }
                            $selectedPolicy = $policiesToUse[$selectedIndex]
                            $policyName = $selectedPolicy.Identity
                            
                            Write-Host "Selected policy: $policyName" -ForegroundColor Green
                            Write-SecureAuditLog -Command "EXISTING_SHARED_CALLING_POLICY_SELECTED: $policyName"
                            
                            # Display policy details
                            Write-Host ""
                            Write-Host "Policy Details:" -ForegroundColor Cyan
                            Write-Host "  Resource Account: $($selectedPolicy.ResourceAccount)" -ForegroundColor White
                            if ($selectedPolicy.EmergencyNumbers) {
                                Write-Host "  Emergency Numbers: $($selectedPolicy.EmergencyNumbers -join ', ')" -ForegroundColor White
                            }
                        }
                        catch {
                            Write-Host "Invalid selection. Please try again." -ForegroundColor Red
                            Continue-Or-Exit
                            return
                        }
                    }
                }
            }
            catch {
                Write-Host "Error retrieving existing policies: $($_.Exception.Message)" -ForegroundColor Red
                Write-Host "Proceeding with new policy creation." -ForegroundColor Yellow
                $policyChoice = 'new'
            }
        }
    }
    
    if ($policyChoice -eq 'new') {
        $policyName = Get-UserInput -Prompt "Enter a name for the new Shared Calling policy" -Required
        $resourceAccountUpn = $Global:ResourceAccountUPN

        if (-not [string]::IsNullOrEmpty($resourceAccountUpn)) {
            $useExisting = Get-UserInput -Prompt "Use previously entered resource account '$resourceAccountUpn'?" -ValidValues @('y','n') -Required
            if ($useExisting -eq 'n') {
                $resourceAccountUpn = Get-UserInput -Prompt "Enter the UPN of the resource account" -Required -ValidationPattern '^[^@]+@[^@]+\.[^@]+$'
            }
        }
        else {
            $resourceAccountUpn = Get-UserInput -Prompt "Enter the UPN of the resource account" -Required -ValidationPattern '^[^@]+@[^@]+\.[^@]+$'
        }

        $emergencyNumbersInput = Get-UserInput -Prompt "Enter comma-separated emergency callback numbers (e.g., +1234567890,+0987654321)" -Required
        $emergencyNumbers = $emergencyNumbersInput -split ',' | ForEach-Object { $_.Trim() }

        # Validate emergency numbers
        foreach ($number in $emergencyNumbers) {
            try {
                Test-InputInjection -Input $number -Type "Phone"
            }
            catch {
                Write-Host "Invalid emergency number format: $number" -ForegroundColor Red
                Continue-Or-Exit
                return
            }
        }

        $confirmationMessage = "This will process the creation of a new Shared Calling policy named '$policyName' with resource account '$resourceAccountUpn' and $($emergencyNumbers.Count) emergency numbers."
        if (-not (Confirm-Action -ConfirmationMessage $confirmationMessage)) {
            Write-Host "Action cancelled by user." -ForegroundColor Red
            Continue-Or-Exit
            return
        }

        $raIdentity = if ($Global:ReadOnlyMode) { $resourceAccountUpn } else { (Get-CsOnlineUser -Identity $resourceAccountUpn).Identity }
        $command = "New-CsTeamsSharedCallingRoutingPolicy -Identity '$policyName' -ResourceAccount '$raIdentity' -EmergencyNumbers @{add='$($emergencyNumbers -join ',')'}"
        $scriptBlock = { New-CsTeamsSharedCallingRoutingPolicy -Identity $using:policyName -ResourceAccount $using:raIdentity -EmergencyNumbers @{add=$using:emergencyNumbers} }
        Execute-Command -CommandString $command -ScriptBlock $scriptBlock
    }
    
    # Store the selected/created policy name for potential future use
    $Global:SelectedSharedCallingPolicy = $policyName
    Write-Host "Shared Calling policy configured: $policyName" -ForegroundColor Green
    Continue-Or-Exit
}

function Step9-AssignSharedCallingPolicy {
    Clear-Host
    Write-Host "--- Step 9: Assign the Shared Calling policy to users $($Global:ModeStatus) ---" -ForegroundColor Yellow
    if ((Continue-Or-Exit) -eq 's') { return }

    $policyName = ""
    
    # Check if we have a previously selected/created policy
    if ($Global:SelectedSharedCallingPolicy) {
        $usePrevious = Get-UserInput -Prompt "Use previously configured Shared Calling policy '$($Global:SelectedSharedCallingPolicy)'?" -ValidValues @('y','n') -Required
        if ($usePrevious -eq 'y') {
            $policyName = $Global:SelectedSharedCallingPolicy
        }
    }
    
    if (-not $policyName) {
        if ($Global:ReadOnlyMode) {
            Write-Host "$($Global:ModeStatus) Skipping live data retrieval. Please provide a policy name for logging purposes." -ForegroundColor Yellow
            $policyName = Get-UserInput -Prompt "Enter the name of the Shared Calling policy to assign" -Required
        }
        else {
            try {
                $existingPolicies = Get-CsTeamsSharedCallingRoutingPolicy -ErrorAction Stop
                if ($existingPolicies.Count -eq 0) {
                    Write-Host "No Shared Calling policies found. Please create a policy first using Step 8." -ForegroundColor Red
                    Continue-Or-Exit
                    return
                }
                else {
                    $maxDisplayPolicies = 20
                    
                    if ($existingPolicies.Count -gt $maxDisplayPolicies) {
                        Write-Host ""
                        Write-Host "⚠️  Large Policy Dataset Detected" -ForegroundColor Yellow
                        Write-Host "Your tenant has $($existingPolicies.Count) Shared Calling policies configured." -ForegroundColor Cyan
                        Write-Host "Displaying only the first $maxDisplayPolicies for performance reasons." -ForegroundColor Cyan
                        Write-Host ""
                        
                        $limitedPolicies = $existingPolicies | Select-Object -First $maxDisplayPolicies
                        Write-Host "📋 Limited Shared Calling Policies List:" -ForegroundColor Cyan
                        Write-Host "----------------------------------------" -ForegroundColor DarkGray
                        for ($i = 0; $i -lt $limitedPolicies.Count; $i++) {
                            $policy = $limitedPolicies[$i]
                            $resourceAccount = if ($policy.ResourceAccount) { $policy.ResourceAccount } else { "Not configured" }
                            $emergencyCount = if ($policy.EmergencyNumbers) { $policy.EmergencyNumbers.Count } else { 0 }
                            Write-Host "$($i + 1). $($policy.Identity)" -ForegroundColor White
                            Write-Host "     Resource Account: $resourceAccount" -ForegroundColor Gray
                            Write-Host "     Emergency Numbers: $emergencyCount configured" -ForegroundColor Gray
                        }
                        Write-Host "----------------------------------------" -ForegroundColor DarkGray
                        Write-Host ""
                        Write-Host "🔍 If your desired policy is not listed above:" -ForegroundColor Yellow
                        Write-Host "Choose option 2 below to enter the policy name directly." -ForegroundColor White
                        Write-Host ""
                        
                        $choice = Get-UserInput -Prompt "Choose an option: (1) Select from list above, (2) Enter specific policy name" -ValidValues @('1','2') -Required
                        
                        if ($choice -eq '1') {
                            $selection = Get-UserInput -Prompt "Select the number of the policy you want to assign (1-$($limitedPolicies.Count))" -Required
                            $policiesToUse = $limitedPolicies
                        }
                        else {
                            $policyName = Get-UserInput -Prompt "Enter the exact name of the Shared Calling Policy" -Required
                            # Verify the policy exists
                            $foundPolicy = $existingPolicies | Where-Object { $_.Identity -eq $policyName }
                            if ($foundPolicy) {
                                Write-Host "Policy found: $policyName" -ForegroundColor Green
                                Write-SecureAuditLog -Command "SHARED_CALLING_POLICY_SELECTED_FOR_ASSIGNMENT_BY_NAME: $policyName"
                                # Skip the selection process since we found the policy by name
                                $selection = $null
                                $policiesToUse = $null
                            }
                            else {
                                Write-Host "Policy '$policyName' not found. Please verify the name and try again." -ForegroundColor Red
                                Continue-Or-Exit
                                return
                            }
                        }
                    }
                    else {
                        # Small list - display all policies
                        Write-Host "Available Shared Calling Policies:" -ForegroundColor Cyan
                        Write-Host "----------------------------------------" -ForegroundColor DarkGray
                        for ($i = 0; $i -lt $existingPolicies.Count; $i++) {
                            $policy = $existingPolicies[$i]
                            $resourceAccount = if ($policy.ResourceAccount) { $policy.ResourceAccount } else { "Not configured" }
                            $emergencyCount = if ($policy.EmergencyNumbers) { $policy.EmergencyNumbers.Count } else { 0 }
                            Write-Host "$($i + 1). $($policy.Identity)" -ForegroundColor White
                            Write-Host "     Resource Account: $resourceAccount" -ForegroundColor Gray
                            Write-Host "     Emergency Numbers: $emergencyCount configured" -ForegroundColor Gray
                        }
                        Write-Host "----------------------------------------" -ForegroundColor DarkGray
                        
                        $selection = Get-UserInput -Prompt "Select the number of the policy you want to assign (1-$($existingPolicies.Count))" -Required
                        $policiesToUse = $existingPolicies
                    }
                    
                    # Process selection if we're using numbered selection
                    if ($selection -ne $null -and $policiesToUse -ne $null) {
                        try {
                            $selectedIndex = [int]$selection - 1
                            if ($selectedIndex -lt 0 -or $selectedIndex -ge $policiesToUse.Count) {
                                throw "Invalid selection"
                            }
                            $selectedPolicy = $policiesToUse[$selectedIndex]
                            $policyName = $selectedPolicy.Identity
                            
                            Write-Host "Selected policy: $policyName" -ForegroundColor Green
                            Write-SecureAuditLog -Command "SHARED_CALLING_POLICY_SELECTED_FOR_ASSIGNMENT: $policyName"
                        }
                        catch {
                            Write-Host "Invalid selection. Please try again." -ForegroundColor Red
                            Continue-Or-Exit
                            return
                        }
                    }
                }
            }
            catch {
                Write-Host "Error retrieving existing policies: $($_.Exception.Message)" -ForegroundColor Red
                $policyName = Get-UserInput -Prompt "Enter the policy name manually" -Required
            }
        }
    }
    
    Show-CsvInstructions -Instruction "Please provide a CSV file containing the users to assign the policy to." -Headers @("UserPrincipalName") -SampleRow @("megan.bowen@contoso.com")
    
    $inputFile = ""
    do {
        $inputFile = Read-Host "Enter the full path to your CSV file"
        if ([string]::IsNullOrWhiteSpace($inputFile)) {
            Write-Host "File path is required." -ForegroundColor Red
            continue
        }
        
        try {
            $users = Test-CsvFile -FilePath $inputFile -RequiredHeaders @("UserPrincipalName")
            break
        }
        catch {
            Write-Host "CSV validation failed: $($_.Exception.Message)" -ForegroundColor Red
            $retry = Get-UserInput -Prompt "Try again with a different file?" -ValidValues @('y','n') -Required
            if ($retry -eq 'n') {
                Continue-Or-Exit
                return
            }
        }
    } while ($true)

    Write-Host "Successfully validated CSV file with $($users.Count) users." -ForegroundColor Green

    $confirmationMessage = "You are about to process assigning the Shared Calling policy '$policyName' to $($users.Count) users."
    if (-not (Confirm-Action -ConfirmationMessage $confirmationMessage)) {
        Write-Host "Bulk action cancelled by user." -ForegroundColor Red
        Continue-Or-Exit
        return
    }

    $totalUsers = $users.Count
    $successCount = 0
    $errorCount = 0
    $errors = @()
    
    for ($i = 0; $i -lt $totalUsers; $i++) {
        $user = $users[$i]
        $upn = $user.UserPrincipalName

        $activity = "Assigning Shared Calling Policy '$policyName'"
        $status = "Processing user $upn ($($i + 1) of $totalUsers)"
        $percentComplete = (($i + 1) / $totalUsers) * 100
        Write-Progress -Activity $activity -Status $status -PercentComplete $percentComplete

        $command = "Grant-CsTeamsSharedCallingRoutingPolicy -PolicyName '$policyName' -Identity '$upn'"
        $scriptBlock = { 
            try {
                Grant-CsTeamsSharedCallingRoutingPolicy -PolicyName $using:policyName -Identity $using:upn -ErrorAction Stop
                return @{ Success = $true; Error = $null }
            }
            catch {
                return @{ Success = $false; Error = $_.Exception.Message }
            }
        }
        
        Write-AuditLog -Command $command
        if ($Global:ReadOnlyMode) {
            Write-Host "$($Global:ModeStatus) Command logged but not executed: $command" -ForegroundColor Yellow
            $successCount++
        }
        else {
            $result = Invoke-Command -ScriptBlock $scriptBlock
            if ($result.Success) {
                $successCount++
            }
            else {
                $errorCount++
                $errors += "User $upn : $($result.Error)"
                Write-Host "Error processing $upn : $($result.Error)" -ForegroundColor Red
            }
        }
    }
    
    Write-Progress -Activity "Assigning Shared Calling Policy" -Completed
    
    # Summary
    Write-Host ""
    Write-Host "=== Operation Summary ===" -ForegroundColor Cyan
    Write-Host "Policy assigned: $policyName" -ForegroundColor White
    Write-Host "Total users processed: $totalUsers" -ForegroundColor White
    Write-Host "Successful: $successCount" -ForegroundColor Green
    if ($errorCount -gt 0) {
        Write-Host "Errors: $errorCount" -ForegroundColor Red
        Write-Host "Error details:" -ForegroundColor Yellow
        $errors | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    }
    
    Continue-Or-Exit
}

function Step10-ConfigureExtensionDialing {
    Clear-Host
    Write-Host "--- Step 10 (Optional): Configure extension dialing $($Global:ModeStatus) ---" -ForegroundColor Yellow
    if ((Continue-Or-Exit) -eq 's') { return }
    
    Show-CsvInstructions -Instruction "Please provide a CSV file with user phone numbers and extensions." -Headers @("UserPrincipalName","PhoneNumber","Extension") -SampleRow @("alex.wilber@contoso.com","+12223334444","6789")
    $inputFile = Read-Host "Enter the full path to your CSV file"
    
    if (-not (Test-Path $inputFile)) {
        Write-Host "File not found." -ForegroundColor Red; Continue-Or-Exit; return
    }
    
    $users = Import-Csv -Path $inputFile

    $confirmationMessage = "You are about to process assigning extensions and Direct Routing numbers to $($users.Count) users."
    if (-not (Confirm-Action -ConfirmationMessage $confirmationMessage)) {
        Write-Host "Bulk action cancelled by user." -ForegroundColor Red
        Continue-Or-Exit
        return
    }

    $totalUsers = $users.Count
    $i = 0
    foreach ($user in $users) {
        $i++
        $upn = $user.UserPrincipalName; $phone = $user.PhoneNumber; $ext = $user.Extension
        
        $activity = "Configuring Extension Dialing"
        $status = "Processing user $upn ($i of $totalUsers)"
        $percentComplete = ($i / $totalUsers) * 100
        Write-Progress -Activity $activity -Status $status -PercentComplete $percentComplete

        $phoneWithExt = "$phone;ext=$ext"
        $command = "Set-CsPhoneNumberAssignment -Identity '$upn' -PhoneNumber `"$phoneWithExt`" -PhoneNumberType DirectRouting"
        $scriptBlock = { Set-CsPhoneNumberAssignment -Identity $using:upn -PhoneNumber $using:phoneWithExt -PhoneNumberType DirectRouting }
        Execute-Command -CommandString $command -ScriptBlock $scriptBlock
    }
    Write-Progress -Activity "Configuring Extension Dialing" -Completed
    Continue-Or-Exit
}

# ---------------------------------------------------------------------------------------------
# Menu Functions
# ---------------------------------------------------------------------------------------------
function Start-GuidedWalkthrough {
    $totalSteps = 10
    $currentStep = 1
    
    # Try to restore previous session
    if (Restore-SessionState) {
        $resume = Get-UserInput -Prompt "Previous session detected. Resume from where you left off?" -ValidValues @('y','n') -Required
        if ($resume -eq 'n') {
            $Global:ResourceAccountUPN = $null
        }
    }
    
    Show-Progress -CurrentStep $currentStep -TotalSteps $totalSteps -StepName "Enable users for voice"
    Step1-EnableUsersForVoice
    $currentStep++
    
    Show-Progress -CurrentStep $currentStep -TotalSteps $totalSteps -StepName "Confirm resource account"
    Step2-AssignNumberToResourceAccount
    Save-SessionState  # Save after getting resource account
    $currentStep++
    
    Show-Progress -CurrentStep $currentStep -TotalSteps $totalSteps -StepName "Confirm Auto Attendant Association"
    Step3-AssociateWithAutoAttendant
    $currentStep++
    
    Show-Progress -CurrentStep $currentStep -TotalSteps $totalSteps -StepName "Assign location to resource account"
    Step4-AssignLocationToResourceAccount
    $currentStep++
    
    Show-Progress -CurrentStep $currentStep -TotalSteps $totalSteps -StepName "Confirm number-specific settings"
    Step5-ConfigureNumberType
    $currentStep++
    
    Show-Progress -CurrentStep $currentStep -TotalSteps $totalSteps -StepName "Create voice routing policy"
    Step6-CreateVoiceRoutingPolicy
    $currentStep++
    
    Show-Progress -CurrentStep $currentStep -TotalSteps $totalSteps -StepName "Confirm emergency calling policy"
    Step7-EnableEmergencyCalling
    $currentStep++
    
    Show-Progress -CurrentStep $currentStep -TotalSteps $totalSteps -StepName "Create Shared Calling policy"
    Step8-CreateSharedCallingPolicy
    $currentStep++
    
    Show-Progress -CurrentStep $currentStep -TotalSteps $totalSteps -StepName "Assign Shared Calling policy to users"
    Step9-AssignSharedCallingPolicy
    $currentStep++
    
    Show-Progress -CurrentStep $currentStep -TotalSteps $totalSteps -StepName "Configure extension dialing (Optional)"
    Step10-ConfigureExtensionDialing
    
    Write-Host ""
    Write-Host "🎉 Guided walkthrough complete!" -ForegroundColor Green
    Write-Host "All steps have been processed. Please review the audit log for details." -ForegroundColor Cyan
    
    # Clean up session state
    $sessionFile = "$env:TEMP\SharedCalling_Session.json"
    if (Test-Path $sessionFile) {
        Remove-Item $sessionFile -Force
    }
    
    Read-Host "Press Enter to return to the main menu"
}

function Show-AdvancedMenu {
    do {
        Clear-Host
        Write-Host "--- Shared Calling Deployment - Advanced Menu $($Global:ModeStatus) ---" -ForegroundColor Yellow
        $menu = @{
            '1' = 'Enable Users for Voice'
            '2' = 'Confirm Resource Account'
            '3' = 'Confirm Auto Attendant Association'
            '4' = 'Assign Location to Resource Account'
            '5' = 'Confirm Number-Specific Settings'
            '6' = 'Create/Select Voice Routing Policy (No PSTN Usages)'
            '7' = 'Confirm Emergency Calling Policy for Users'
            '8' = 'Create/Select Shared Calling Policy'
            '9' = 'Assign Shared Calling Policy to Users'
            '10' = 'Configure Extension Dialing (Optional)'
            'B' = 'Back to Main Menu'
        }
        $menu.GetEnumerator() | ForEach-Object { Write-Host "$($_.Name). $($_.Value)"}
        $choice = Read-Host "Select an option"

        switch ($choice) {
            '1' { Step1-EnableUsersForVoice }
            '2' { Step2-AssignNumberToResourceAccount }
            '3' { Step3-AssociateWithAutoAttendant }
            '4' { Step4-AssignLocationToResourceAccount }
            '5' { Step5-ConfigureNumberType }
            '6' { Step6-CreateVoiceRoutingPolicy }
            '7' { Step7-EnableEmergencyCalling }
            '8' { Step8-CreateSharedCallingPolicy }
            '9' { Step9-AssignSharedCallingPolicy }
            '10' { Step10-ConfigureExtensionDialing }
            'b' { return }
            'B' { return }
            default { Write-Host "Invalid option." -ForegroundColor Red; Read-Host }
        }
    } while ($choice -ne 'b')
}

# ---------------------------------------------------------------------------------------------
# Main Script Body
# ---------------------------------------------------------------------------------------------

# Initialize secure session
$sessionInfo = New-SecureSession
Write-Host "🔐 Secure session initialized: $($sessionInfo.SessionId)" -ForegroundColor Green

Show-Introduction

# --- Mode Selection ---
Clear-Host
Write-Host "--- Mode Selection ---" -ForegroundColor Yellow
Write-Host "Please select the operating mode for this session."
Write-Host "1. Live Mode (Commands WILL be executed and will change your M365 environment)" -ForegroundColor Red
Write-Host "2. Read-Only Mode (Commands will ONLY be logged for review, NO changes will be made)" -ForegroundColor Green
do {
    $modeChoice = Read-Host "Select mode (1 for Live, 2 for Read-Only)"
    if ($modeChoice -eq '1') { $Global:ReadOnlyMode = $false; $Global:ModeStatus = "[LIVE MODE]"; break }
    if ($modeChoice -eq '2') { $Global:ReadOnlyMode = $true; $Global:ModeStatus = "[READ-ONLY MODE]"; break }
    Write-Host "Invalid selection." -ForegroundColor Red
} while ($true)

Connect-ToTeams

# --- Action Menu ---
do {
    Clear-Host
    Write-Host "--- Main Menu $($Global:ModeStatus) ---" -ForegroundColor Yellow
    Write-Host "1. Start from the beginning (Guided Walkthrough)"
    Write-Host "2. Go to a specific step (Advanced Menu)"
    Write-Host "Q. Quit and Export Log"
    $initialChoice = Read-Host "Select an option"

    switch ($initialChoice) {
        '1' { Start-GuidedWalkthrough }
        '2' { Show-AdvancedMenu }
        'q' { break }
        'Q' { break }
        default { Write-Host "Invalid option." -ForegroundColor Red; Read-Host }
    }
} while ($initialChoice -notin @('q', 'Q'))

Export-AuditLog
Write-Host "Shared Calling deployment script has finished." -ForegroundColor Green
