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
# Global Variable Initialization
# ---------------------------------------------------------------------------------------------
$Global:AuditLog = [System.Collections.ArrayList]@()
$Global:ReadOnlyMode = $false
$Global:ModeStatus = ""
$Global:ResourceAccountUPN = $null

# ---------------------------------------------------------------------------------------------
# Helper, Auditing, and Export Functions
# ---------------------------------------------------------------------------------------------
function Write-AuditLog {
    param(
        [string]$Command
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] COMMAND: $Command"
    $Global:AuditLog.Add($logEntry) | Out-Null
}

function Export-AuditLog {
    if ($Global:AuditLog.Count -eq 0) {
        Write-Host "No actions were logged during this session." -ForegroundColor Yellow
        return
    }

    $saveChoice = Read-Host "An audit log of actions is available. Do you want to save it? (y/n)"
    if ($saveChoice -eq 'y') {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $defaultPath = "$HOME\Desktop\SharedCalling_AuditLog_$timestamp.txt"
        $savePath = Read-Host "Enter the full path to save the log file (default: $defaultPath)"
        
        if ([string]::IsNullOrWhiteSpace($savePath)) {
            $savePath = $defaultPath
        }

        try {
            # Add header to log file indicating the mode
            $logHeader = "--- Audit Log Generated in $($Global:ModeStatus.ToUpper()) ---"
            $logContent = $logHeader + [System.Environment]::NewLine + ($Global:AuditLog -join [System.Environment]::NewLine)
            $logContent | Out-File -FilePath $savePath
            Write-Host "Audit log successfully saved to $savePath" -ForegroundColor Green
        }
        catch {
            Write-Host "Failed to save audit log." -ForegroundColor Red
            Write-Host $_.Exception.Message -ForegroundColor Red
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

    Write-Host "Attempting to connect to Microsoft Teams PowerShell..." -ForegroundColor Cyan
    try {
        Import-Module MicrosoftTeams -ErrorAction Stop
        Connect-MicrosoftTeams -LogLevel INFO
        Write-Host "Successfully connected to Microsoft Teams." -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to connect to Microsoft Teams. Please ensure the module is installed and you have the correct permissions." -ForegroundColor Red
        Read-Host "Press Enter to exit..."
        exit
    }
}

# ---------------------------------------------------------------------------------------------
# Step Functions with Auditing
# ---------------------------------------------------------------------------------------------

function Step1-EnableUsersForVoice {
    Clear-Host
    Write-Host "--- Step 1: Enable users for voice $($Global:ModeStatus) ---" -ForegroundColor Yellow
    Write-Host ""
    if ((Continue-Or-Exit) -eq 's') { return }
    
    Write-Host "This step ensures users have a Teams Phone license and are enabled for Enterprise Voice."
    
    Show-CsvInstructions -Instruction "Please provide a CSV file containing the users to enable for voice." -Headers @("UserPrincipalName") -SampleRow @("adele.vance@contoso.com")
    $inputFile = Read-Host "Enter the full path to your CSV file"

    if (-not (Test-Path $inputFile)) {
        Write-Host "File not found." -ForegroundColor Red; Continue-Or-Exit; return
    }

    $users = Import-Csv -Path $inputFile
    
    $confirmationMessage = "You are about to process enabling Enterprise Voice for $($users.Count) users from the file '$inputFile'."
    if (-not (Confirm-Action -ConfirmationMessage $confirmationMessage)) {
        Write-Host "Bulk action cancelled by user." -ForegroundColor Red
        Continue-Or-Exit
        return
    }

    $totalUsers = $users.Count
    $i = 0
    foreach ($user in $users) {
        $i++
        $upn = $user.UserPrincipalName
        
        $activity = "Enabling Enterprise Voice"
        $status = "Processing user $upn ($i of $totalUsers)"
        $percentComplete = ($i / $totalUsers) * 100
        Write-Progress -Activity $activity -Status $status -PercentComplete $percentComplete

        $command = "Set-CsPhoneNumberAssignment -Identity '$upn' -EnterpriseVoiceEnabled `$true"
        $scriptBlock = { Set-CsPhoneNumberAssignment -Identity $using:upn -EnterpriseVoiceEnabled $true }
        Execute-Command -CommandString $command -ScriptBlock $scriptBlock
    }
    Write-Progress -Activity "Enabling Enterprise Voice" -Completed
    Continue-Or-Exit
}

function Step2-AssignNumberToResourceAccount {
    Clear-Host
    Write-Host "--- Step 2: Confirm resource account $($Global:ModeStatus) ---" -ForegroundColor Yellow
    if ((Continue-Or-Exit) -eq 's') { return }
    
    $resourceAccountUpn = Read-Host "Enter the UPN of the resource account"
    $command = "Get-CsOnlineUser -Identity '$resourceAccountUpn'"
    Write-AuditLog -Command $command
    if ($Global:ReadOnlyMode) {
        Write-Host "$($Global:ModeStatus) Command to verify resource account was logged." -ForegroundColor Yellow
        $Global:ResourceAccountUPN = $resourceAccountUpn
    }
    else {
        try {
            Get-CsOnlineUser -Identity $resourceAccountUpn | Out-Null
            Write-Host "Successfully verified resource account '$resourceAccountUpn' exists." -ForegroundColor Green
            $Global:ResourceAccountUPN = $resourceAccountUpn
        }
        catch {
             Write-Host "Could not find resource account '$resourceAccountUpn'." -ForegroundColor Red
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
        if ((Read-Host "Use previously entered resource account '$resourceAccountUpn'? (y/n)") -ne 'y') {
            $resourceAccountUpn = Read-Host "Enter the UPN of the resource account"
        }
    }
    else {
        $resourceAccountUpn = Read-Host "Enter the UPN of the resource account"
    }

    if ($Global:ReadOnlyMode) {
        Write-Host "$($Global:ModeStatus) Skipping live data retrieval. Please provide a placeholder Location ID for logging purposes." -ForegroundColor Yellow
        $locationId = Read-Host "Enter a placeholder Location ID"
    }
    else {
        Get-CsOnlineLisLocation | Format-Table Location, LocationId
        $locationId = Read-Host "Enter the Location ID from the list above"
    }
    
    $confirmationMessage = "This will process the assignment of location ID '$locationId' to resource account '$resourceAccountUpn'."
    if (-not (Confirm-Action -ConfirmationMessage $confirmationMessage)) {
        Write-Host "Action cancelled by user." -ForegroundColor Red
        Continue-Or-Exit
        return
    }

    $command = "Set-CsPhoneNumberAssignment -Identity '$resourceAccountUpn' -LocationId '$locationId'"
    $scriptBlock = { Set-CsPhoneNumberAssignment -Identity $using:resourceAccountUpn -LocationId $using:locationId }
    Execute-Command -CommandString $command -ScriptBlock $scriptBlock
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
    
    $policyName = Read-Host "Enter a name for the new, empty voice routing policy"

    $confirmationMessage = "This will process the creation of a new voice routing policy named '$policyName'."
    if (-not (Confirm-Action -ConfirmationMessage $confirmationMessage)) {
        Write-Host "Action cancelled by user." -ForegroundColor Red
        Continue-Or-Exit
        return
    }

    $command = "New-CsOnlineVoiceRoutingPolicy -Identity '$policyName' -OnlinePstnUsages @()"
    $scriptBlock = { New-CsOnlineVoiceRoutingPolicy -Identity $using:policyName -OnlinePstnUsages @() }
    Execute-Command -CommandString $command -ScriptBlock $scriptBlock
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

    $policyName = Read-Host "Enter a name for the new Shared Calling policy"
    $resourceAccountUpn = $Global:ResourceAccountUPN

    if (-not [string]::IsNullOrEmpty($resourceAccountUpn)) {
        if ((Read-Host "Use previously entered resource account '$resourceAccountUpn'? (y/n)") -ne 'y') {
            $resourceAccountUpn = Read-Host "Enter the UPN of the resource account"
        }
    }
    else {
        $resourceAccountUpn = Read-Host "Enter the UPN of the resource account"
    }

    $emergencyNumbersInput = Read-Host "Enter comma-separated emergency callback numbers"
    $emergencyNumbers = $emergencyNumbersInput -split ',' | ForEach-Object { $_.Trim() }

    $confirmationMessage = "This will process the creation of a new Shared Calling policy named '$policyName'."
    if (-not (Confirm-Action -ConfirmationMessage $confirmationMessage)) {
        Write-Host "Action cancelled by user." -ForegroundColor Red
        Continue-Or-Exit
        return
    }

    $raIdentity = if ($Global:ReadOnlyMode) { $resourceAccountUpn } else { (Get-CsOnlineUser -Identity $resourceAccountUpn).Identity }
    $command = "New-CsTeamsSharedCallingRoutingPolicy -Identity '$policyName' -ResourceAccount '$raIdentity' -EmergencyNumbers @{add='$($emergencyNumbers -join ',')'}"
    $scriptBlock = { New-CsTeamsSharedCallingRoutingPolicy -Identity $using:policyName -ResourceAccount $using:raIdentity -EmergencyNumbers @{add=$using:emergencyNumbers} }
    Execute-Command -CommandString $command -ScriptBlock $scriptBlock
    Continue-Or-Exit
}

function Step9-AssignSharedCallingPolicy {
    Clear-Host
    Write-Host "--- Step 9: Assign the Shared Calling policy to users $($Global:ModeStatus) ---" -ForegroundColor Yellow
    if ((Continue-Or-Exit) -eq 's') { return }

    $policyName = ""
    if ($Global:ReadOnlyMode) {
        Write-Host "$($Global:ModeStatus) Skipping live data retrieval. Please provide a policy name for logging purposes." -ForegroundColor Yellow
        $policyName = Read-Host "Enter the name of the Shared Calling policy to assign"
    }
    else {
        Get-CsTeamsSharedCallingRoutingPolicy | Select-Object Identity
        $policyName = Read-Host "Enter the policy name to assign from the list"
    }
    
    Show-CsvInstructions -Instruction "Please provide a CSV file containing the users to assign the policy to." -Headers @("UserPrincipalName") -SampleRow @("megan.bowen@contoso.com")
    $inputFile = Read-Host "Enter the full path to your CSV file"

    if (-not (Test-Path $inputFile)) {
        Write-Host "File not found." -ForegroundColor Red; Continue-Or-Exit; return
    }

    $users = Import-Csv -Path $inputFile

    $confirmationMessage = "You are about to process assigning the Shared Calling policy '$policyName' to $($users.Count) users."
    if (-not (Confirm-Action -ConfirmationMessage $confirmationMessage)) {
        Write-Host "Bulk action cancelled by user." -ForegroundColor Red
        Continue-Or-Exit
        return
    }

    $totalUsers = $users.Count
    $i = 0
    foreach ($user in $users) {
        $i++
        $upn = $user.UserPrincipalName

        $activity = "Assigning Shared Calling Policy '$policyName'"
        $status = "Processing user $upn ($i of $totalUsers)"
        $percentComplete = ($i / $totalUsers) * 100
        Write-Progress -Activity $activity -Status $status -PercentComplete $percentComplete

        $command = "Grant-CsTeamsSharedCallingRoutingPolicy -PolicyName '$policyName' -Identity '$upn'"
        $scriptBlock = { Grant-CsTeamsSharedCallingRoutingPolicy -PolicyName $using:policyName -Identity $using:upn }
        Execute-Command -CommandString $command -ScriptBlock $scriptBlock
    }
    Write-Progress -Activity "Assigning Shared Calling Policy" -Completed
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
        $scriptBlock = { Set-CsPhoneNumberahoneNumberAssignment -Identity $using:upn -PhoneNumber $using:phoneWithExt -PhoneNumberType DirectRouting }
        Execute-Command -CommandString $command -ScriptBlock $scriptBlock
    }
    Write-Progress -Activity "Configuring Extension Dialing" -Completed
    Continue-Or-Exit
}

# ---------------------------------------------------------------------------------------------
# Menu Functions
# ---------------------------------------------------------------------------------------------
function Start-GuidedWalkthrough {
    Step1-EnableUsersForVoice
    Step2-AssignNumberToResourceAccount
    Step3-AssociateWithAutoAttendant
    Step4-AssignLocationToResourceAccount
    Step5-ConfigureNumberType
    Step6-CreateVoiceRoutingPolicy
    Step7-EnableEmergencyCalling
    Step8-CreateSharedCallingPolicy
    Step9-AssignSharedCallingPolicy
    Step10-ConfigureExtensionDialing
    Write-Host "Guided walkthrough complete." -ForegroundColor Green
    Read-Host "Press Enter to return to the main menu."
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
            '6' = 'Create Voice Routing Policy (No PSTN Usages)'
            '7' = 'Confirm Emergency Calling Policy for Users'
            '8' = 'Create Shared Calling Policy'
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
            default { Write-Host "Invalid option." -ForegroundColor Red; Read-Host }
        }
    } while ($choice -ne 'b')
}

# ---------------------------------------------------------------------------------------------
# Main Script Body
# ---------------------------------------------------------------------------------------------
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
        default { Write-Host "Invalid option." -ForegroundColor Red; Read-Host }
    }
} while ($initialChoice -ne 'q')

Export-AuditLog
Write-Host "Shared Calling deployment script has finished." -ForegroundColor Green
