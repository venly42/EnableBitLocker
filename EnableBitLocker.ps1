<#
.SYNOPSIS
    Comprehensive script for automating BitLocker encryption and UEFI Secure Boot updates with multi-vendor OEM device BIOS configuration support.

.DESCRIPTION
    This script performs the following main functions:
    
    1. **BitLocker Status Detection and Enablement**
       - Detects BitLocker protection status for all drives
       - Enables BitLocker encryption on unprotected drives (using XtsAes256 encryption method)
       - Generates and manages BitLocker recovery keys
    
    
    2. **UEFI CA 2023 Detection**
       - Detects Windows UEFI CA 2023 certificate installation status
       - If installed, directly enables BitLocker and exits
       - If not installed, continues with SecureBoot configuration process
    
    3. **Multi-Vendor OEM Support**
       - Dell: Uses Dell Command Configure (CCTK) tool
       - Lenovo: Uses ThinkBiosConfig.hta tool
       - HP: Basic support (functionality pending enhancement)
       - Automatically identifies OEM vendor and downloads appropriate BIOS configuration tools
    
    4. **SecureBoot Configuration**
       - Detects current SecureBoot status
       - Uses vendor-specific tools to enable SecureBoot
       - Supports multiple file download methods (local share, remote share, Internet download)
    
    5. **System Configuration and Task Scheduling**
       - Modifies registry settings to trigger UEFI updates
       - Starts Windows scheduled tasks to execute SecureBoot updates
       - Complete logging and error handling mechanisms

.EXECUTION FLOW
    Main Script Logic Flow (Updated as of v1.9):
    
    [START] --> Step 0: TPM compatibility check
                     |
                     v
            TPM ready? --> NO --> [EXIT 2]
                     |
                     YES
                     v
            Step 1: BitLocker protection status check
                     |
                     v
            All drives protected? --> YES -->
                     - Detect locked data drives (manage-bde cross-check)
                     - Unlock with recovery key --> if success: Enable Auto‑Unlock (OS protection gated)
                     - Enable Auto‑Unlock for eligible data drives (FullyEncrypted & ProtectionStatus=On; OS gate)
                     - Clean temp folders --> [EXIT 0]
                     |
                     NO
                     v
            Remediate locked data drives (unprotected branch)
                     - Detect lock via cmdlets/manage-bde, unlock with recovery key
                     - Enable Auto‑Unlock gated by OS protection
                     |
                     v
            Step 2: Check Windows UEFI CA 2023
                     |
                     v
            Certificate installed? --> YES -->
                     - Categorize drives: `C:` serial, data drives parallel (fallback to serial)
                     - Enable BitLocker and collect results
                     - Short retry for transient errors
                     - Final guard: fresh protection check; if all protected --> [EXIT 0]
                     - If none succeeded, mark deferred retry and continue to Step 3
                     |
                     NO --> Continue to Step 3
                     |
                     v
            Step 3: SecureBoot status and OEM processing
                     |
                     v
            SecureBoot enabled? --> YES -->
                     - Configure registry --> Start update task
                     - If deferred retry marked: save `ProgramData\BitLocker\Retry.json` --> [EXIT 3]
                     |
                     NO -->
                     - Detect OEM (Dell/Lenovo/HP/Other)
                     - Dell: Download/sync CCTK, run `cctk --SecureBoot=Enabled`, then registry + task; if deferred retry: save mark --> [EXIT 3]
                     - Lenovo: Download/sync ThinkBiosConfig, run SecureBoot commands, then registry + task; if deferred retry: save mark --> [EXIT 3]
                     - HP: Log TODO (manual may be required)
                     - Other: Unsupported OEM --> [EXIT 2]
                     |
                     v
            [Script completion and final logging]
    
    Key Decision Points:
    • TPM readiness gate (Step 0)
    • BitLocker protection gate (Step 1) with locked-drive remediation
    • UEFI CA 2023 certificate gate (Step 2) with parallel enablement and fallback
    • SecureBoot status (Step 3) and OEM-specific branches
    • Final guard: fresh protection check to skip SecureBoot when already protected
    
    Exit Codes:
    • 0: Success (all protected or enablement completed)
    • 1: BitLocker enablement returned no results
    • 2: TPM incompatible/not ready or unsupported OEM
    • 3: Deferred BitLocker retry after SecureBoot update (Retry.json saved)
    
    Error Handling Strategy:
    • Continue execution despite non-critical failures
    • Log all operations with detailed status information
    • Use exit codes to indicate different completion states
    • Implement retry mechanisms for network and parallel operations

.PARAMETERS
    LogsPath - Log file storage path (Default: \\mjcs23\MISProject\EnableBitLocker\Logs\)
    LocalSharedPath - Local shared file path (Default: \\mjcs23\MISProject\EnableBitLocker\)
    RemoteSharedPath - Remote shared file path (Default: \\mcs85\UEFIUpdate\)
    DefaultDownloadPath - Default Internet download URL

.AUTHOR
    [Author]

.DATE
    Version 1.9 - October 14, 2025

.VERSION
    1.1 - Refactored version with enhanced logging system and error handling
    1.2 - Added Auto-Lock function into the Function of Enable-UnprotectedDrives
    1.3 - Added the function of Test-WindowsUEFICA2023 and Test-SecureBootEnabled
        - Test-WindowsUEFICA2023: Detects Windows UEFI CA 2023 certificate installation status
        - Test-SecureBootEnabled: Detects current SecureBoot status 
        - Set-SecureBootRegistryConfiguration: Sets SecureBoot registry configuration
        - Start-SecureBootUpdateTask: Starts SecureBoot update task
        - Adjust the main execution process to include SecureBoot configuration steps
        - Enhanced Dell and Lenovo SecureBoot enablement process: After successfully enabling SecureBoot via CCTK or ThinkBiosConfig commands, the script now immediately executes Set-SecureBootRegistryConfiguration and Start-SecureBootUpdateTask functions instead of waiting for the next script execution.
        - Improved efficiency: Eliminates the need for manual intervention after SecureBoot enablement, reducing overall execution time.
        - Ensures immediate registry configuration and task scheduling: Configures registry settings and schedules tasks immediately after SecureBoot enablement, eliminating the delay caused by waiting for the next script execution.
    1.4 - Enhanced BitLocker enablement process with improved status verification and error handling
        - Optimized status verification logic: Replaced multiple Enable-BitLocker retry attempts with single execution followed by multiple status verification attempts
        - Added PartialSuccess status handling: Introduced new status type for cases where BitLocker enables successfully but recovery key extraction fails
        - Enhanced result processing: Main execution flow now properly handles Success, PartialSuccess, and Failed states with appropriate logging
        - Improved summary statistics: Enable-UnprotectedDrives function now provides comprehensive statistics including partial success counts and detailed error reporting
        - Fixed step numbering: Corrected the sequence of auto-unlock (Step 4) and recovery key retrieval (Step 5) operations
        - Optimized Sleep positioning: Moved status verification delays to occur only when retries are needed, improving first-attempt efficiency
        - Code cleanup: Removed unused variables ($hasSuccess, $bitlockerResult, $schtaskResult) to eliminate IDE warnings and improve code quality
        - Enhanced error handling: Removed misplaced exit statements and improved script flow continuity
    1.5 - Optimized Enable-UnprotectedDrives function and improved script exit logic
        - Fixed auto-unlock logic indentation and exception handling: Corrected code structure and improved error handling in the auto-unlock process
        - Enhanced error handling mechanisms: Improved exception catching and logging throughout the function
        - Optimized wait time intervals: Standardized sleep intervals and reduced unnecessary delays for better performance
        - Added empty drive list validation: Added boundary condition checks to handle cases where no unprotected drives are found
        - Optimized status verification logic: Added caching for BitLocker status to reduce API calls, reduced retry attempts from 5 to 3, and decreased interval time from 15 to 10 seconds
        - Improved script exit strategy: Modified exit conditions to terminate script when any drive is successfully encrypted (including partial success), eliminating unnecessary SecureBoot update processes and improving execution efficiency
        - Fixed temporary folder cleanup logic: Corrected the issue where only one folder existence was checked but two folders were deleted, now properly checks each folder (BitLockerTemp and BitLockerDeploy) individually before deletion
        - Enhanced cleanup error handling: Added try-catch blocks for temporary folder deletion operations to prevent script termination due to cleanup failures, with proper success/warning logging
    1.6 - Code quality improvements and PowerShell best practices compliance
        - Fixed syntax errors: Resolved parameter block positioning issue by moving param block before variable declarations
        - Removed unused parameters: Eliminated TPMInitializationDelay and GeneralOperationDelay parameters that were declared but never used
        - Improved variable scoping: Replaced global variables ($global:DellCCTKFileLists, $global:LenovoBIOSConfigFileLists) with script-scoped variables ($script:) for better encapsulation
        - Resolved function naming conflicts: Renamed custom Write-Log function to Write-ScriptLog to avoid conflicts with PowerShell built-in cmdlets
        - Enhanced code maintainability: All changes improve PSScriptAnalyzer compliance and follow PowerShell coding best practices
        - Verified script integrity: Confirmed all syntax errors are resolved and script can be parsed and executed successfully
    1.7 - Documentation and code analysis improvements
        - Performed comprehensive code review covering syntax validation, logic verification, error handling analysis, variable scope inspection, and performance optimization
        - Validated Watch-BitLockerStatus function timeout mechanism parameters and their proper usage throughout the codebase
        - Confirmed script robustness with proper exception handling, resource management, and production-ready standards
        - Enhanced documentation includes parallel processing architecture, error handling workflows, and monitoring integration details
    1.8 - Parallel BitLocker processing implementation and optimization
        - Added Enable-ParallelBitLocker.ps1 module: Implemented comprehensive parallel processing system for multiple drive BitLocker enablement
        - Three-phase parallel processing architecture: Phase 1 (Parallel BitLocker enablement), Phase 2 (Parallel monitoring and AutoUnlock), Phase 3 (Results aggregation and statistics)
        - Enhanced performance: Significantly improved efficiency when processing multiple data drives simultaneously instead of sequential processing
        - Intelligent fallback mechanism: Automatic fallback to original serial processing if parallel module fails to load, ensuring backward compatibility
        - Independent monitoring system: Each drive gets dedicated monitoring with individual timeout controls and progress tracking
        - Immediate AutoUnlock enablement: AutoUnlock is enabled immediately after BitLocker activation without waiting for full encryption completion
        - Comprehensive error handling: Enhanced error detection, logging, and recovery mechanisms throughout the parallel processing workflow
        - Real-time progress reporting: Detailed logging and status updates for each drive's encryption progress and completion status
        - Resource optimization: Efficient job management and cleanup to prevent resource leaks during parallel operations

    1.8.3 - Auto-Unlock gating and OS protection wait
        - Added Wait-ForOSBitLockerProtection helper: Polls OS drive C: until ProtectionStatus=On (default: 30s poll, indefinite wait); configurable wait and detailed precheck logging
        - Introduced Enable-DataDriveAutoUnlock wrapper: Enforces OS protection precheck before enabling Auto-Unlock, verifies success post-command, and unifies logging
        - Replaced direct Enable-BitLockerAutoUnlock calls for data drives with Enable-DataDriveAutoUnlock across the script (Step 1 all-protected flow, parallel monitoring completion, final compensation phase, and Watch-BitLockerStatus)
        - Prevents premature Auto-Unlock attempts that caused 0x80310020 when OS volume was not protected; actions are now deferred until OS is protected or a configurable timeout occurs
        - Monitoring updates: Logs reflect Auto-Unlock precheck, success, and warning states for clearer diagnostics
        - EXE/GPO compatibility: Monitoring jobs no longer dot-source ps1; function definitions are injected into job runspaces to avoid file path dependency when compiled to EXE and run via Scheduled Task (SYSTEM)

    1.9 - Locked data drive compensation and recovery-key unlock flow
        - Added compensation logic in Step 1 (AllProtected branch): Detect locked data volumes via Get-ManageBdeStatusInfo, unlock using Unlock-DataDriveIfLocked (reads recovery key from C:\BitLockerRecoveryKeys), then enable Auto-Unlock via Enable-DataDriveAutoUnlock
        - Unified logging and statistics: Tracks processed volumes, unlock successes/failures, and Auto-Unlock enablement states with concise summary output
        - Execution flow documentation updated: All-protected path now includes locked-drive detection, recovery-key unlock, and OS-gated Auto-Unlock enablement before cleanup
        - Internationalized status parsing maintained: Get-ManageBdeStatusInfo continues to support bilingual (EN/ZH) field matching for lock/protection states
        - No code-path changes outside compensation flow: Normal Auto-Unlock enablement for fully encrypted, protected data drives remains intact

.NOTES
    System Requirements:
    - Requires administrator privileges to execute system settings and registry modifications
    - Requires network connection or access to local/remote network shares for downloading tools
    - Supports Windows 10/11 operating systems
    - Requires UEFI firmware support (does not support legacy BIOS)
    
    Security Features:
    - BitLocker recovery key information is masked in logs for security
    - Supports retry mechanisms and error recovery
    - Complete operation auditing and status tracking
    
    Important Notes:
    - Script does not perform actual UEFI updates, but configures the system to execute updates on reboot
    - Strongly recommended to test thoroughly before production environment deployment
    - BitLocker encryption process may take considerable time depending on drive size
    - Ensure important data is backed up before execution

#
.FUNCTIONS PARAM/RETURN
    Core helper functions used by this script and their inputs/outputs:
    
    - Initialize-LogFile
      Parameters: `LogDirectory` (string, optional; default `SCRIPT_CONSTANTS.DEFAULT_LOG_DIRECTORY`)
      Returns: `string` absolute path to the log file.

    - Write-ScriptLog
      Parameters: `LogFilePath` (string), `Message` (string)
      Returns: none (writes one line to the log file with timestamp and host).

    - Test-BitLockerProtection
      Parameters: none
      Returns: `PSCustomObject` with `AllProtected` (bool) and `UnprotectedDrives` (string[]).

    - Wait-ForOSBitLockerProtection
      Parameters: `PollSeconds` (int, default `30`), `MaxWaitSeconds` (int, default `0` = wait indefinitely)
      Returns: `bool` (true when OS drive `C:` protection is On; false on timeout/error).

    - Enable-DataDriveAutoUnlock
      Parameters: `MountPoint` (string)
      Returns: `bool` (true if Auto‑Unlock enabled and verified; false otherwise)
      Notes: Skips `C:`; ensures the OS drive is protected first; verifies `AutoUnlockEnabled`.

    - Unlock-DataDriveIfLocked
      Parameters: `MountPoint` (string), `RecoveryKeyPath` (string, default `C:\BitLockerRecoveryKeys`)
      Returns: `bool` (true if unlock succeeds; false otherwise)
      Notes: Parses recovery password from `${Drive}-RecoveryKey.txt` and runs `manage-bde -unlock`.

    - Reset-DataDriveAutoUnlock
      Parameters: `MountPoint` (string), `LogFile` (string)
      Returns: `bool` (true if disable+enable cycle succeeds and verification passes)
      Notes: Requires the volume to be unlocked before resetting.

    - Get-ManageBdeStatusInfo
      Parameters: `MountPoint` (string), `LogFile` (string)
      Returns: `hashtable` with keys: `Raw` (string), `PercentageEncrypted` (int or null), `LockStatus` (string),
               `ProtectionStatus` (string), `ConversionStatus` (string), `AutoUnlock` (string), `EncryptionMethod` (string), `BitLockerVersion` (string).

    - Watch-BitLockerStatus
      Parameters: `MountPoint` (string), `IntervalSeconds` (int, default `30`), `TimeoutSeconds` (int, default `21600`),
                  `LogFile` (string), `OnSuccess` (scriptblock, optional), `OnTimeout` (scriptblock, optional)
      Returns: `bool` (true when encryption completes with protection On; false on timeout)
      Notes: Immediately returns true for `C:`; in non‑interactive contexts callbacks are skipped; enables Auto‑Unlock for data drives via `Enable-DataDriveAutoUnlock` upon success.

    - Enable-UnprotectedDrives
      Parameters: `UnprotectedDrives` (string[]), `RecoveryKeyPath` (string, default), `LogFile` (string, default)
      Returns: `PSCustomObject[]` where each item may include: `Drive`, `RecoveryKeyId`, `RecoveryPassword`, `Status`
               (`Success`, `PartialSuccess`, `Failed`, `MonitorTimeout`, `MonitorError`, `AutoUnlockFailed`, `Critical_TPM_Error`),
               `ErrorMessage` (string, optional), `AutoUnlockEnabled` (bool, when applicable), `IsSystemDrive` (bool), `SubmittedToForms` (bool, when applicable).
      Notes: Creates BitLocker jobs, monitors completion, exports recovery keys, enables Auto‑Unlock for data drives, and ensures TPM protector on OS drive.

    - Enable-OsDriveTpmProtector
      Parameters: `MountPoint` (string, default `C:`), `LogFile` (string)
      Returns: `bool` (true if TPM protector exists or is added; false otherwise).

    - Invoke-ExternalCommand
      Parameters: `WorkingDirectory` (string), `Command` (string), `TimeoutSeconds` (int, optional)
      Returns: `bool` (true on `exitCode=0`; false otherwise; times out for long‑running/interactive commands).

#>


param(
    [Parameter(HelpMessage="Log file path for storing logs")]
    [string]$LogsPath = "\\SERVER\Logs\BitLocker\",
    [Parameter(HelpMessage="Local file path for downloading tools")]
    [string]$LocalSharedPath = "\\SERVER\Tools\BitLocker\",
    [Parameter(HelpMessage="Remote file path for downloading tools")]
    [string]$RemoteSharedPath = "\\SERVER\Updates\BitLocker\",
    [Parameter(HelpMessage="Default Internet Download URL for tools")]
    [string]$DefaultDownloadPath  = "https://example.com/tools",
    [Parameter(HelpMessage="Recovery key storage path for BitLocker")]
    [string]$RecoveryKeyPath = "$env:SystemDrive\BitLockerRecoveryKeys",
    [Parameter(HelpMessage="Sleep time in seconds for status recheck after UserInteractive error")]
    [int]$UserInteractiveRecheckDelay = 15,
    [Parameter(HelpMessage="Sleep time in seconds between BitLocker status verification retries")]
    [int]$StatusVerificationRetryDelay = 10
)

# Script Constants
$SCRIPT_CONSTANTS = @{
    # BitLocker Status Values
    BITLOCKER_STATUS_ENCRYPTED = @('EncryptionInProgress', 'FullyEncrypted')
    BITLOCKER_ENCRYPTION_METHOD = 'XtsAes256'
    
    # Retry Configuration
    MAX_STATUS_RETRIES = 3
    MAX_LOG_RETRIES = 3
    
    # TPM Error Codes
    TPM_COMPATIBILITY_ERROR_CODE = '0x80284000'
    
    # File Extensions and Paths
    LOG_FILE_EXTENSION = '.log'
    RECOVERY_KEY_FOLDER = 'BitLockerRecoveryKeys'
    DEFAULT_LOG_DIRECTORY = "\\SERVER\Logs\BitLocker\"
    FALLBACK_LOG_FILENAME = "BitLocker_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    
    # Task and Registry Names
    SECUREBOOT_TASK_NAME = 'SecureBootUpdate'
    TASK_NAME = "EnableBitLocker_Task"
    
    # Common Error Messages
    ERROR_USERINTERACTIVE = @('UserInteractive', 'ServiceNotification', 'DefaultDesktopOnly')
    ERROR_MESSAGES = @{
        TPM_NOT_COMPATIBLE = "TPM is not compatible with BitLocker encryption"
        USERINTERACTIVE_ERROR = "UserInteractive mode error detected"
        ENCRYPTION_FAILED = "BitLocker encryption failed"
    }
}


# Script Functions
function Enable-ParallelBitLocker {
   
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$UnprotectedDrives,   

        [string]$RecoveryKeyPath = "$env:SystemDrive\BitLockerRecoveryKeys", 
        [string]$LogFile = "$env:SystemDrive\BitLockerEnable.log",
        [int]$MonitorIntervalSeconds = 30,
        [int]$MonitorTimeoutSeconds = 7200
    )

    Write-ScriptLog -LogFilePath $LogFile -Message "=== Starting Parallel BitLocker Enablement Process ==="
    
    # Validate input parameters
    if ($null -eq $UnprotectedDrives -or $UnprotectedDrives.Count -eq 0) {
        Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] No drives provided for BitLocker enablement"
        return @()
    }
    
    # Filter valid drives (exclude system drive C:)
    $validDataDrives = $UnprotectedDrives | Where-Object { 
        -not [string]::IsNullOrWhiteSpace($_) -and ($_.Trim().TrimEnd(':') + ":") -ne "C:" 
    }
    
    if ($validDataDrives.Count -eq 0) {
        Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] No valid data drives found after filtering"
        return @()
    }
    
    Write-ScriptLog -LogFilePath $LogFile -Message "Total data drives to process: $($validDataDrives.Count)"
    Write-ScriptLog -LogFilePath $LogFile -Message "Data drives to encrypt: $($validDataDrives -join ', ')"
    
    # Prepare recovery key directory
    Write-ScriptLog -LogFilePath $LogFile -Message "[STEP 1] Preparing recovery key directory: $RecoveryKeyPath"
    if (-not (Test-Path $RecoveryKeyPath)) {
        try {
            New-Item -ItemType Directory -Path $RecoveryKeyPath -Force | Out-Null
            Write-ScriptLog -LogFilePath $LogFile -Message "[SUCCESS] Recovery key directory created successfully"
        } catch {
            Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] Failed to create recovery key directory: $RecoveryKeyPath. Error: $_"
            $RecoveryKeyPath = "$env:SystemDrive\"
        }
    }

    # ==================== Phase 1: Start BitLocker Jobs in Parallel ====================
    Write-ScriptLog -LogFilePath $LogFile -Message "[PHASE 1] Starting parallel BitLocker enablement jobs..."
    
    $bitlockerJobs = @()
    $encryptionMethod = "XtsAes256"
    
    # BitLocker enablement job script block
    $jobScriptBlock = {
        param($MountPoint, $EncryptionMethod, $LogFile)
        
        Import-Module BitLocker -Force -DisableNameChecking
        
        try {
            Enable-BitLocker -MountPoint $MountPoint `
                           -RecoveryPasswordProtector `
                           -SkipHardwareTest `
                           -EncryptionMethod $EncryptionMethod `
                           -Confirm:$false `
                           -ErrorAction Stop
            
            return @{
                Success = $true
                MountPoint = $MountPoint
                Message = "BitLocker enabled successfully"
                ErrorMessage = $null
            }
        } catch {
            $errorMessage = $_.Exception.Message
            
            # Check if this is a UserInteractive error (should be treated as warning)
            $isUserInteractiveError = $false
            $uiErrorKeywords = @('UserInteractive', 'ServiceNotification', 'DefaultDesktopOnly')
            foreach ($uiErrorKeyword in $uiErrorKeywords) {
                if ($errorMessage -like "*$uiErrorKeyword*") {
                    $isUserInteractiveError = $true
                    break
                }
            }
            
            if ($isUserInteractiveError) {
                # UserInteractive error - log as warning but still return success to continue processing
                return @{
                    Success = $true
                    MountPoint = $MountPoint
                    Message = "BitLocker enabled with UserInteractive warning (expected in non-interactive mode)"
                    ErrorMessage = "WARNING: $errorMessage"
                    IsUserInteractiveWarning = $true
                }
            } else {
                # Other errors - return as failure
                return @{
                    Success = $false
                    MountPoint = $MountPoint
                    Message = "BitLocker enablement failed"
                    ErrorMessage = $errorMessage
                }
            }
        }
    }
    
    # Start BitLocker jobs for all data drives in parallel
    foreach ($drive in $validDataDrives) {
        $normalizedDrive = $drive.Trim().TrimEnd(':') + ":"
        
        try {
            Write-ScriptLog -LogFilePath $LogFile -Message "[PARALLEL START] Creating BitLocker job for $normalizedDrive"
            
            $job = Start-Job -ScriptBlock $jobScriptBlock -ArgumentList $normalizedDrive, $encryptionMethod, $LogFile
            
            $bitlockerJobs += @{
                Job = $job
                Drive = $normalizedDrive
                StartTime = Get-Date
                Status = "JobRunning"
                MonitoringStarted = $false
                EncryptionCompleted = $false
                AutoUnlockEnabled = $false
            }
            
            Write-ScriptLog -LogFilePath $LogFile -Message "[SUCCESS] BitLocker job created for $normalizedDrive (Job ID: $($job.Id))"
        } catch {
            Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] Failed to create BitLocker job for $normalizedDrive : $($_.Exception.Message)"
        }
    }
    
    Write-ScriptLog -LogFilePath $LogFile -Message "[PHASE 1 COMPLETE] All BitLocker jobs started. Total jobs: $($bitlockerJobs.Count)"
    
    # ==================== Phase 2: Parallel Monitoring and AutoUnlock ====================
    Write-ScriptLog -LogFilePath $LogFile -Message "[PHASE 2] Starting parallel monitoring and AutoUnlock process..."
    
    $results = @()
    $monitoringStartTime = Get-Date
    $globalTimeout = $MonitorTimeoutSeconds + 1800  # Global timeout: per-drive timeout + 30 minutes buffer
    
    # Main monitoring loop
    while ($bitlockerJobs.Count -gt 0) {
        $currentTime = Get-Date
        $globalElapsed = ($currentTime - $monitoringStartTime).TotalSeconds
        
        # Check global timeout
        if ($globalElapsed -gt $globalTimeout) {
            Write-ScriptLog -LogFilePath $LogFile -Message "[WARNING] Global monitoring timeout reached after $([math]::Round($globalElapsed/3600, 1)) hours"
            break
        }
        
        $jobsToRemove = @()
        
        foreach ($jobInfo in $bitlockerJobs) {
            $job = $jobInfo.Job
            $drive = $jobInfo.Drive
            $jobElapsed = ($currentTime - $jobInfo.StartTime).TotalSeconds
            
            # Check if BitLocker enablement job is completed
            if ($jobInfo.Status -eq "JobRunning" -and $job.State -ne "Running") {
                Write-ScriptLog -LogFilePath $LogFile -Message "[JOB COMPLETE] BitLocker job completed for $drive"
                
                # Get job results with non-interactive mode
                try {
                    # Set non-interactive mode before receiving job output
                    $ProgressPreference = 'SilentlyContinue'
                    $WarningPreference = 'SilentlyContinue'
                    $VerbosePreference = 'SilentlyContinue'
                    $DebugPreference = 'SilentlyContinue'
                    $InformationPreference = 'SilentlyContinue'
                    
                    $jobOutput = Receive-Job -Job $job -ErrorAction Stop -WarningAction SilentlyContinue
                    Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
                } catch {
                    $errorMessage = $_.Exception.Message
                    Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] Failed to receive job output for $drive : $errorMessage"
                    Write-ScriptLog -LogFilePath $LogFile -Message "[DEBUG] Exception type: $($_.Exception.GetType().FullName)"
                    
                    # Check if this is a UserInteractive error (which may not be a real failure)
                    if ($errorMessage -like "*UserInteractive*" -or $errorMessage -like "*显示模式对话框或窗体是无效操作*") {
                        Write-ScriptLog -LogFilePath $LogFile -Message "[WARNING] UserInteractive error detected - treating as warning, not failure"
                        Write-ScriptLog -LogFilePath $LogFile -Message "[INFO] Attempting to verify BitLocker status directly for $drive"
                        
                        # Try to verify BitLocker status directly
                        try {
                            $directStatus = Get-BitLockerVolume -MountPoint $drive -ErrorAction Stop
                            # BitLocker is considered successful if:
                            # 1. EncryptionInProgress (encryption started successfully)
                            # 2. FullyEncrypted with Protection On (fully completed)
                            if ($directStatus.VolumeStatus -eq "EncryptionInProgress") {
                                Write-ScriptLog -LogFilePath $LogFile -Message "[SUCCESS] BitLocker encryption in progress for $drive - Status: $($directStatus.VolumeStatus), Progress: $($directStatus.EncryptionPercentage)%"
                                # Create a successful output with warning flag
                                $jobOutput = @{ 
                                    Success = $true
                                    IsUserInteractiveWarning = $true
                                    ErrorMessage = "UserInteractive warning (BitLocker encryption started successfully): $errorMessage"
                                    MountPoint = $drive
                                    EncryptionProgress = $directStatus.EncryptionPercentage
                                }
                            } elseif ($directStatus.VolumeStatus -eq "FullyEncrypted" -and $directStatus.ProtectionStatus -eq "On") {
                                Write-ScriptLog -LogFilePath $LogFile -Message "[SUCCESS] BitLocker fully encrypted for $drive - Status: $($directStatus.VolumeStatus), Protection: $($directStatus.ProtectionStatus)"
                                # Create a successful output with warning flag
                                $jobOutput = @{ 
                                    Success = $true
                                    IsUserInteractiveWarning = $true
                                    ErrorMessage = "UserInteractive warning (BitLocker fully encrypted): $errorMessage"
                                    MountPoint = $drive
                                }
                            } else {
                                Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] BitLocker verification failed for $drive - Status: $($directStatus.VolumeStatus), Protection: $($directStatus.ProtectionStatus)"
                                $jobOutput = @{ Success = $false; ErrorMessage = "BitLocker verification failed after UserInteractive error: Status=$($directStatus.VolumeStatus), Protection=$($directStatus.ProtectionStatus)" }
                            }
                        } catch {
                            Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] Failed to verify BitLocker status for $drive : $($_.Exception.Message)"
                            $jobOutput = @{ Success = $false; ErrorMessage = "Failed to verify BitLocker status after UserInteractive error: $($_.Exception.Message)" }
                        }
                    } else {
                        # For other types of errors, create a standard failed output
                        $jobOutput = @{ Success = $false; ErrorMessage = "Failed to receive job output: $errorMessage" }
                    }
                    
                    # Try to remove job anyway
                    try { Remove-Job -Job $job -Force -ErrorAction SilentlyContinue } catch { }
                }
                
                if ($jobOutput.Success) {
                    if ($jobOutput.IsUserInteractiveWarning) {
                        Write-ScriptLog -LogFilePath $LogFile -Message "[WARNING] BitLocker enabled for $drive with UserInteractive warning: $($jobOutput.ErrorMessage)"
                    } else {
                        Write-ScriptLog -LogFilePath $LogFile -Message "[SUCCESS] BitLocker enabled successfully for $drive"
                    }
                    $jobInfo.Status = "BitLockerEnabled"

                    # Immediately export recovery key once protectors exist (Phase 1 requirement)
                    try {
                        $currentStatus = Get-BitLockerVolume -MountPoint $drive -ErrorAction Stop
                        $protector = $currentStatus | Select-Object -ExpandProperty KeyProtector
                        $recoveryKeyProtector = ($protector | Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" } | Select-Object -First 1)

                        if ($recoveryKeyProtector) {
                            if (-not (Test-Path $RecoveryKeyPath)) {
                                try { New-Item -ItemType Directory -Path $RecoveryKeyPath -Force | Out-Null } catch {}
                            }
                            $recoveryKeyFile = "$RecoveryKeyPath\$($drive.TrimEnd(':'))-RecoveryKey.txt"
                            $recoveryKeyContent = @"
BitLocker Recovery Key for Drive $drive
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Computer: $env:COMPUTERNAME

Key Protector ID: $($recoveryKeyProtector.KeyProtectorId)
Recovery Password: $($recoveryKeyProtector.RecoveryPassword)

Instructions:
1. Use this recovery password if you cannot unlock the drive normally
2. Keep this information in a secure location
3. The recovery password is case-sensitive
"@
                            $recoveryKeyContent | Out-File -FilePath $recoveryKeyFile -Encoding UTF8 -Force
                            Write-ScriptLog -LogFilePath $LogFile -Message "[SUCCESS] (Phase 1) Recovery key exported to: $recoveryKeyFile"
                            $jobInfo.RecoveryKeyId = $recoveryKeyProtector.KeyProtectorId
                            $jobInfo.RecoveryPassword = $recoveryKeyProtector.RecoveryPassword
                        } else {
                            Write-ScriptLog -LogFilePath $LogFile -Message "[WARNING] (Phase 1) Recovery password protector not found for $drive"
                        }
                    } catch {
                        Write-ScriptLog -LogFilePath $LogFile -Message "[WARNING] (Phase 1) Failed to export recovery key immediately for $drive : $($_.Exception.Message)"
                    }
                } else {
                    Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] BitLocker enablement failed for $drive : $($jobOutput.ErrorMessage)"
                    $jobInfo.Status = "Failed"
                    $jobInfo.ErrorMessage = $jobOutput.ErrorMessage
                    if (-not ($jobsToRemove | Where-Object { $_.Drive -eq $jobInfo.Drive })) { $jobsToRemove += $jobInfo }
                    continue
                }
            }
            
            # Start monitoring drives with BitLocker enabled
            if ($jobInfo.Status -eq "BitLockerEnabled" -and -not $jobInfo.MonitoringStarted) {
                Write-ScriptLog -LogFilePath $LogFile -Message "[MONITOR START] Starting encryption monitoring for $drive"
                $jobInfo.MonitoringStarted = $true
                $jobInfo.Status = "Monitoring"
            }
            
            # Monitor encryption progress
            if ($jobInfo.Status -eq "Monitoring" -and -not $jobInfo.EncryptionCompleted) {
                try {
                    $bitlockerStatus = Get-BitLockerVolume -MountPoint $drive -ErrorAction Stop
                    $encryptionPercent = $bitlockerStatus.EncryptionPercentage
                    $protectionStatus = $bitlockerStatus.ProtectionStatus
                    $volumeStatus = $bitlockerStatus.VolumeStatus
                    
                    Write-ScriptLog -LogFilePath $LogFile -Message "[MONITOR] $drive - Status: $volumeStatus - Encryption: $encryptionPercent% - Protection: $protectionStatus"
                    
                    # Check if encryption is complete
                    if ($encryptionPercent -eq 100 -and $protectionStatus.ToString() -eq "On") {
                        Write-ScriptLog -LogFilePath $LogFile -Message "[ENCRYPTION COMPLETE] $drive encryption finished successfully"
                        $jobInfo.EncryptionCompleted = $true
                        $jobInfo.Status = "EncryptionComplete"
                        
                        # Export recovery key
                        try {
                            $protector = $bitlockerStatus | Select-Object -ExpandProperty KeyProtector
                            $recoveryKeyProtector = ($protector | Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" } | Select-Object -First 1)
                            
                            if ($recoveryKeyProtector) {
                                $recoveryKeyFile = "$RecoveryKeyPath\$($drive.TrimEnd(':'))-RecoveryKey.txt"
                                $recoveryKeyContent = @"
BitLocker Recovery Key for Drive $drive
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Computer: $env:COMPUTERNAME

Key Protector ID: $($recoveryKeyProtector.KeyProtectorId)
Recovery Password: $($recoveryKeyProtector.RecoveryPassword)

Instructions:
1. Use this recovery password if you cannot unlock the drive normally
2. Keep this information in a secure location
3. The recovery password is case-sensitive
"@
                                $recoveryKeyContent | Out-File -FilePath $recoveryKeyFile -Encoding UTF8 -Force
                                Write-ScriptLog -LogFilePath $LogFile -Message "[SUCCESS] Recovery key exported to: $recoveryKeyFile"
                                
                                $jobInfo.RecoveryKeyId = $recoveryKeyProtector.KeyProtectorId
                                $jobInfo.RecoveryPassword = $recoveryKeyProtector.RecoveryPassword
                            }
                        } catch {
                            Write-ScriptLog -LogFilePath $LogFile -Message "[WARNING] Failed to export recovery key for $drive : $($_.Exception.Message)"
                        }
                    }
                    
                    # Check individual drive monitoring timeout
                    if ($jobElapsed -gt $MonitorTimeoutSeconds) {
                        Write-ScriptLog -LogFilePath $LogFile -Message "[WARNING] Monitoring timeout for $drive after $([math]::Round($jobElapsed/3600, 1)) hours"
                        $jobInfo.Status = "MonitorTimeout"
                    }
                    
                } catch {
                    Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] Failed to check BitLocker status for $drive : $($_.Exception.Message)"
                    $jobInfo.Status = "MonitorError"
                    $jobInfo.ErrorMessage = $_.Exception.Message
                }
            }
            
            # Enable AutoUnlock
            if ($jobInfo.Status -eq "EncryptionComplete" -and -not $jobInfo.AutoUnlockEnabled) {
                $enabled = Enable-DataDriveAutoUnlock -MountPoint $drive
                if ($enabled) {
                    $jobInfo.AutoUnlockEnabled = $true
                    $jobInfo.Status = "Complete"
                    if (-not ($jobsToRemove | Where-Object { $_.Drive -eq $jobInfo.Drive })) { $jobsToRemove += $jobInfo }
                } else {
                    $jobInfo.Status = "AutoUnlockFailed"
                    if (-not ($jobsToRemove | Where-Object { $_.Drive -eq $jobInfo.Drive })) { $jobsToRemove += $jobInfo }
                }
            }
            
            # Handle various completion or error states
            if ($jobInfo.Status -in @("Complete", "Failed", "MonitorTimeout", "MonitorError", "AutoUnlockFailed")) {
                if (-not ($jobsToRemove | Where-Object { $_.Drive -eq $jobInfo.Drive })) { $jobsToRemove += $jobInfo }
            }
        }
        
        # Remove completed jobs and add to results
        foreach ($completedJob in $jobsToRemove) {
            $bitlockerJobs = $bitlockerJobs | Where-Object { $_.Drive -ne $completedJob.Drive }
            
            $results += [PSCustomObject]@{
                Drive            = $completedJob.Drive
                RecoveryKeyId    = $completedJob.RecoveryKeyId
                RecoveryPassword = $completedJob.RecoveryPassword
                Status           = $completedJob.Status
                ErrorMessage     = $completedJob.ErrorMessage
                AutoUnlockEnabled = $completedJob.AutoUnlockEnabled
                IsSystemDrive    = $false
            }
            
            Write-ScriptLog -LogFilePath $LogFile -Message "[COMPLETED] Processing finished for $($completedJob.Drive) with status: $($completedJob.Status)"
        }
        
        # If there are still jobs running, wait for a while before checking again
        if ($bitlockerJobs.Count -gt 0) {
            Start-Sleep -Seconds $MonitorIntervalSeconds
        }
    }
    
    # ==================== Phase 3: Results Summary ====================
    Write-ScriptLog -LogFilePath $LogFile -Message "[PHASE 3] Parallel BitLocker process completed"
    Write-ScriptLog -LogFilePath $LogFile -Message "=== Parallel BitLocker Enablement Process Complete ==="
    
    # Summary statistics
    $successCount = ($results | Where-Object { $_.Status -eq "Complete" }).Count
    $failedCount = ($results | Where-Object { $_.Status -in @("Failed", "MonitorError", "AutoUnlockFailed") }).Count
    $timeoutCount = ($results | Where-Object { $_.Status -eq "MonitorTimeout" }).Count
    
    Write-ScriptLog -LogFilePath $LogFile -Message "[SUMMARY] Total drives processed: $($results.Count)"
    Write-ScriptLog -LogFilePath $LogFile -Message "[SUMMARY] Successful: $successCount, Failed: $failedCount, Timeout: $timeoutCount"
    
    return $results
}


function Initialize-LogFile {
    param(
        [string]$LogDirectory = $SCRIPT_CONSTANTS.DEFAULT_LOG_DIRECTORY
    )

    if (-not (Test-Path $LogDirectory)) {
        $LogDirectory = $env:TEMP
    }

    $ComputerName = $env:COMPUTERNAME
    $LogFileName  = "${ComputerName}.log"
    $LogFile      = Join-Path $LogDirectory $LogFileName

    try {
        if (-not (Test-Path $LogDirectory)) {
            New-Item -Path $LogDirectory -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }

        if (-not (Test-Path $LogFile)) {
            New-Item -Path $LogFile -ItemType File -Force -ErrorAction Stop | Out-Null
        }
    }
    catch {
        $LogDirectory = $env:TEMP
        $LogFile = Join-Path $LogDirectory $LogFileName
        try {
            New-Item -Path $LogFile -ItemType File -Force -ErrorAction SilentlyContinue | Out-Null
        } catch {
            $LogFile = Join-Path $env:TEMP $SCRIPT_CONSTANTS.FALLBACK_LOG_FILENAME
            New-Item -Path $LogFile -ItemType File -Force -ErrorAction SilentlyContinue | Out-Null
        }
    }

    return $LogFile
}


function Write-ScriptLog {
    param(
        [string]$LogFilePath,
        [string]$Message
    )
    $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $HostName = $env:COMPUTERNAME
    $LogEntry = "$TimeStamp - $HostName - $Message"

    # Retry mechanism to handle file access issues
    $maxRetries = 3
    $retryCount = 0
    $success = $false
    
    while (-not $success -and $retryCount -lt $maxRetries) {
        try {
            # Ensure the directory exists
            $logDirectory = Split-Path -Path $LogFilePath -Parent
            if (-not (Test-Path -Path $logDirectory)) {
                New-Item -Path $logDirectory -ItemType Directory -Force | Out-Null
            }
            
            # Use Out-File with Append parameter to avoid stream conflicts
            $LogEntry | Out-File -FilePath $LogFilePath -Append -Encoding UTF8 -ErrorAction Stop
            $success = $true
        }
        catch {
            $retryCount++
            if ($retryCount -lt $maxRetries) {
                # Wait briefly before retrying
                Start-Sleep -Milliseconds (100 * $retryCount)
            } else {
                # Final attempt failed, write to console as fallback
                Write-Host "[LOG ERROR] Failed to write to log file after $maxRetries attempts: $($_.Exception.Message)" -ForegroundColor Yellow
                Write-Host "[LOG FALLBACK] $LogEntry" -ForegroundColor Gray
            }
        }
    }
}


function New-TempPath {
    [CmdletBinding()]
    param (
        [string]$FolderName = (New-Guid).ToString()
    )

    $fullPath = Join-Path -Path $env:TEMP -ChildPath $FolderName

    try {
        $null = New-Item -Path $fullPath -ItemType Directory -Force -ErrorAction Stop
        Write-ScriptLog -LogFilePath $LogFile -Message "Create the temp folder successfully: $fullPath"
    } catch {
        Write-ScriptLog -LogFilePath $LogFile -Message "Failed to create the temp folder, and the error message is $($_.Exception.Message)"

    }

    return $fullPath
}


function Start-RandomSleep {
    param(
        [int]$Min = 1,
        [int]$Max = 10
    )
    $randomNumber = Get-Random -Minimum $Min -Maximum $Max
    Start-Sleep -Seconds $randomNumber
}


function Test-WindowsUEFICA2023 {
    try {
        Write-ScriptLog -LogFilePath $LogFile -Message "[DEBUG] Entering Test-WindowsUEFICA2023"

        $db = Get-SecureBootUEFI -Name db -ErrorAction Stop

        if ($null -eq $db -or $null -eq $db.Bytes) {
            Write-ScriptLog -LogFilePath $LogFile -Message "SecureBoot DB object or bytes is null."
            return $false
        }

        $text = [System.Text.Encoding]::ASCII.GetString($db.Bytes)
        #$preview = if ($text.Length -gt 100) { $text.Substring(0,100) + "..." } else { $text }
        #Write-ScriptLog -LogFilePath $LogFile -Message "[DEBUG] SecureBoot DB (ASCII preview): $preview"

        if ($text -match "Windows UEFI CA 2023") {
            Write-ScriptLog -LogFilePath $LogFile -Message "SecureBoot DB has been updated (contains Windows UEFI CA 2023)."
            return $true
        }
        else {
            Write-ScriptLog -LogFilePath $LogFile -Message "SecureBoot DB has not been updated (Windows UEFI CA 2023 not found)."
            return $false
        }
    }
    catch {
        Write-ScriptLog -LogFilePath $LogFile -Message "Test-WindowsUEFICA2023 failed: $($_.Exception.Message)"
        return $false
    }
    finally {
        Write-ScriptLog -LogFilePath $LogFile -Message "[DEBUG] Leaving Test-WindowsUEFICA2023"
    }
}


function Test-BitLockerProtection {
    [CmdletBinding()]
    param()

    Write-ScriptLog -LogFilePath $LogFile -Message "=== Starting BitLocker Protection Status Check ==="  
    
    try {
        $volumes = Get-BitLockerVolume | Where-Object { ($_.VolumeType -eq 'Data') -or ($_.VolumeType -eq 'OperatingSystem') }
        Write-ScriptLog -LogFilePath $LogFile -Message "Found $($volumes.Count) eligible volume(s) to analyze"
        
        $unprotected = @()
        $protected = @()
        $totalDataVolumes = 0
        $protectedDataVolumes = 0
        $totalSystemVolumes = 0
        $protectedSystemVolumes = 0

        foreach ($volume in $volumes) {
            # Compute reliable size via Get-Volume fallback to avoid 0 GB when CapacityGB is missing
            $sizeGb = $null
            try {
                $driveLetter = $volume.MountPoint.TrimEnd(':')
                if ($driveLetter -match '^[A-Z]$') {
                    $driveInfo = Get-Volume -DriveLetter $driveLetter -ErrorAction SilentlyContinue
                    if ($driveInfo) { $sizeGb = [math]::Round(($driveInfo.Size/1GB), 2) }
                }
            } catch { }
            if ($null -eq $sizeGb) { $sizeGb = [math]::Round($volume.CapacityGB, 2) }

            # If status fields are unavailable in non-interactive context, log and skip classification
            if ([string]::IsNullOrWhiteSpace($volume.ProtectionStatus) -and [string]::IsNullOrWhiteSpace($volume.VolumeStatus)) {
                $typeLabel = $volume.VolumeType
                $volumeInfo = "Volume: $($volume.MountPoint) | Type: $typeLabel | Status: $($volume.ProtectionStatus) | VolumeStatus: $($volume.VolumeStatus) | EncryptionPercentage: $($volume.EncryptionPercentage)%"
                Write-ScriptLog -LogFilePath $LogFile -Message "[INFO] $typeLabel $volumeInfo | Size: $sizeGb GB (status unavailable, skip unprotected classification)"
                continue
            }

            $volumeInfo = "Volume: $($volume.MountPoint) | Type: $($volume.VolumeType) | Status: $($volume.ProtectionStatus) | VolumeStatus: $($volume.VolumeStatus) | EncryptionPercentage: $($volume.EncryptionPercentage)%"
            
            if ($volume.VolumeType -eq "Data") {
                $totalDataVolumes++
                # Protected only when BitLocker is ON and volume is FullyEncrypted
                if ($volume.ProtectionStatus -eq 'On' -and $volume.VolumeStatus -eq 'FullyEncrypted') {
                    $protectedDataVolumes++
                    $protected += $volume.MountPoint
                    Write-ScriptLog -LogFilePath $LogFile -Message "[PROTECTED] Data $volumeInfo | Encryption: $($volume.EncryptionMethod)"
                }
                elseif ($volume.VolumeStatus -eq 'EncryptionInProgress') {
                    $unprotected += $volume.MountPoint
                    Write-ScriptLog -LogFilePath $LogFile -Message "[ENCRYPTING] Data $volumeInfo | Size: $sizeGb GB"
                }
                elseif ($volume.VolumeStatus -eq 'FullyDecrypted' -or $volume.ProtectionStatus -ne 'On') {
                    $unprotected += $volume.MountPoint
                    Write-ScriptLog -LogFilePath $LogFile -Message "[UNPROTECTED] Data $volumeInfo | Size: $sizeGb GB"
                }
                else {
                    # Unknown/other statuses are treated as not fully protected
                    $unprotected += $volume.MountPoint
                    Write-ScriptLog -LogFilePath $LogFile -Message "[INFO] Data $volumeInfo | Status: $($volume.VolumeStatus)"
                }
            }
            elseif ($volume.VolumeType -eq "OperatingSystem") {
                $totalSystemVolumes++
                # Protected only when BitLocker is ON and volume is FullyEncrypted
                if ($volume.ProtectionStatus -eq 'On' -and $volume.VolumeStatus -eq 'FullyEncrypted') {
                    $protectedSystemVolumes++
                    $protected += $volume.MountPoint
                    Write-ScriptLog -LogFilePath $LogFile -Message "[PROTECTED] System $volumeInfo | Encryption: $($volume.EncryptionMethod)"
                }
                elseif ($volume.VolumeStatus -eq 'EncryptionInProgress') {
                    $unprotected += $volume.MountPoint
                    Write-ScriptLog -LogFilePath $LogFile -Message "[ENCRYPTING] System $volumeInfo | Size: $sizeGb GB"
                }
                elseif ($volume.VolumeStatus -eq 'FullyDecrypted' -or $volume.ProtectionStatus -ne 'On') {
                    $unprotected += $volume.MountPoint
                    Write-ScriptLog -LogFilePath $LogFile -Message "[UNPROTECTED] System $volumeInfo | Size: $sizeGb GB"
                }
                else {
                    # Unknown/other statuses are treated as not fully protected
                    $unprotected += $volume.MountPoint
                    Write-ScriptLog -LogFilePath $LogFile -Message "[INFO] System $volumeInfo | Status: $($volume.VolumeStatus)"
                }
            }
        }
        
        # Summary report
        Write-ScriptLog -LogFilePath $LogFile -Message "--- BitLocker Protection Summary ---"
        Write-ScriptLog -LogFilePath $LogFile -Message "System Volumes: $protectedSystemVolumes/$totalSystemVolumes protected"
        Write-ScriptLog -LogFilePath $LogFile -Message "Data Volumes: $protectedDataVolumes/$totalDataVolumes protected"
        Write-ScriptLog -LogFilePath $LogFile -Message "Total Protected Volumes: $($protected.Count)"
        Write-ScriptLog -LogFilePath $LogFile -Message "Total Unprotected Volumes: $($unprotected.Count)"
        
        # Gate by explicit unprotected count to avoid false triggers when status fields are missing
        $allProtected = ($unprotected.Count -eq 0)
        if ($allProtected) {
            Write-ScriptLog -LogFilePath $LogFile -Message "[SUCCESS] All eligible volumes are BitLocker protected"
        } else {
            Write-ScriptLog -LogFilePath $LogFile -Message "[ACTION REQUIRED] $($unprotected.Count) volume(s) need BitLocker protection"
        }
        
        Write-ScriptLog -LogFilePath $LogFile -Message "=== BitLocker Protection Status Check Complete ==="
        
    } catch {
        Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] Failed to check BitLocker protection status: $($_.Exception.Message)"
        Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] Error Type: $($_.Exception.GetType().FullName)"
        Write-ScriptLog -LogFilePath $LogFile -Message "[FALLBACK] Assuming all drives need BitLocker protection due to detection failure"
        
        # Return a safe fallback result
        return [PSCustomObject]@{
            AllProtected = $false
            UnprotectedDrives = @("C:", "D:")  # Common drive letters as fallback
        }
    }

    if ($allProtected) {
        return [PSCustomObject]@{
            AllProtected = $true
            UnprotectedDrives = @()
        }
    } else {
        return [PSCustomObject]@{
            AllProtected = $false
            UnprotectedDrives = $unprotected
        }
    }
}


function Get-SecureBootStatus {
    [CmdletBinding()]
    param()
    try {
        $secureBootStatus = Confirm-SecureBootUEFI
        if($secureBootStatus) {
            Write-ScriptLog -LogFilePath $LogFile -Message "Secure Boot is enabled."
            return $true
        } else {
            Write-ScriptLog -LogFilePath $LogFile -Message "Secure Boot is not enabled."
            return $false
        }
    }
    catch {
        Write-ScriptLog -LogFilePath $LogFile -Message "Secure Boot is not supported, or an error occurred: $_"
        return $false
        }
}


# Ensures the OS drive (default C:) has a TPM-based protector so it can auto-unlock at boot.
function Enable-OsDriveTpmProtector {
    [CmdletBinding()]
    param(
        [string]$MountPoint = "C:",
        [string]$LogFile
    )

    try {
        Write-ScriptLog -LogFilePath $LogFile -Message "[TPM PROTECTOR] Verifying TPM-based protector presence on $MountPoint"

        $vol = Get-BitLockerVolume -MountPoint $MountPoint -ErrorAction Stop
        $keyProtectors = $vol.KeyProtector
        $hasTpm = $false

        if ($keyProtectors) {
            foreach ($kp in $keyProtectors) {
                if ($kp.KeyProtectorType -in @("Tpm", "TpmPin", "TpmAndPin")) { $hasTpm = $true; break }
            }
        }

        if ($hasTpm) {
            Write-ScriptLog -LogFilePath $LogFile -Message "[SUCCESS] TPM-based protector already present on $MountPoint"
            return $true
        }

        # Check TPM readiness before attempting to add protector
        $tpmStatus = Get-Tpm -ErrorAction SilentlyContinue
        if (-not $tpmStatus -or -not $tpmStatus.TpmPresent) {
            Write-ScriptLog -LogFilePath $LogFile -Message "[WARNING] TPM not present or not accessible; cannot add TPM protector to $MountPoint"
            return $false
        }
        if (-not $tpmStatus.TpmReady) {
            Write-ScriptLog -LogFilePath $LogFile -Message "[WARNING] TPM present but not ready (Enabled: $($tpmStatus.TpmEnabled), Activated: $($tpmStatus.TpmActivated)); cannot add TPM protector to $MountPoint"
            return $false
        }

        try {
            Add-BitLockerKeyProtector -MountPoint $MountPoint -TpmProtector -ErrorAction Stop | Out-Null
            Write-ScriptLog -LogFilePath $LogFile -Message "[SUCCESS] Added TPM protector to $MountPoint"
            return $true
        } catch {
            Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] Failed to add TPM protector to ${MountPoint}: $($_.Exception.Message)"
            return $false
        }
    } catch {
        Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] TPM protector verification failed on ${MountPoint}: $($_.Exception.Message)"
        return $false
    }
}


function Get-OEMInfo {
    [CmdletBinding()]
    param()

    Write-ScriptLog -LogFilePath $LogFile -Message "=== Detecting OEM Hardware Information ==="
    
    try {
        Write-ScriptLog -LogFilePath $LogFile -Message "[STEP 1] Querying Win32_ComputerSystem for hardware details..."
        
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $manufacturer = $cs.Manufacturer
        $model = $cs.Model
        
        Write-ScriptLog -LogFilePath $LogFile -Message "[SUCCESS] Hardware information retrieved successfully"
        Write-ScriptLog -LogFilePath $LogFile -Message "Raw Manufacturer: '$manufacturer'"
        Write-ScriptLog -LogFilePath $LogFile -Message "Raw Model: '$model'"
        
        # Normalize manufacturer name for better recognition
        $normalizedManufacturer = switch -Regex ($manufacturer) {
            "Dell.*" { "Dell"; Write-ScriptLog -LogFilePath $LogFile -Message "[INFO] Detected Dell system" }
            "Lenovo.*" { "Lenovo"; Write-ScriptLog -LogFilePath $LogFile -Message "[INFO] Detected Lenovo system" }
            "Hewlett.*|HP.*" { "HP"; Write-ScriptLog -LogFilePath $LogFile -Message "[INFO] Detected HP system" }
            "Microsoft.*" { "Microsoft"; Write-ScriptLog -LogFilePath $LogFile -Message "[INFO] Detected Microsoft Surface system" }
            "ASUS.*" { "ASUS"; Write-ScriptLog -LogFilePath $LogFile -Message "[INFO] Detected ASUS system" }
            "Acer.*" { "Acer"; Write-ScriptLog -LogFilePath $LogFile -Message "[INFO] Detected Acer system" }
            default { $manufacturer; Write-ScriptLog -LogFilePath $LogFile -Message "[INFO] Unknown/Other manufacturer: $manufacturer" }
        }
        
        # Get additional system information
        Write-ScriptLog -LogFilePath $LogFile -Message "[STEP 2] Gathering additional system details..."
        
        try {
            $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue
            if ($bios) {
                Write-ScriptLog -LogFilePath $LogFile -Message "BIOS Version: $($bios.SMBIOSBIOSVersion)"
                Write-ScriptLog -LogFilePath $LogFile -Message "BIOS Release Date: $($bios.ReleaseDate)"
                Write-ScriptLog -LogFilePath $LogFile -Message "Serial Number: $($bios.SerialNumber)"
            }
        } catch {
            Write-ScriptLog -LogFilePath $LogFile -Message "[WARNING] Could not retrieve BIOS information: $($_.Exception.Message)"
        }
        
        try {
            $baseBoard = Get-CimInstance -ClassName Win32_BaseBoard -ErrorAction SilentlyContinue
            if ($baseBoard) {
                Write-ScriptLog -LogFilePath $LogFile -Message "Motherboard Product: $($baseBoard.Product)"
                Write-ScriptLog -LogFilePath $LogFile -Message "Motherboard Version: $($baseBoard.Version)"
            }
        } catch {
            Write-ScriptLog -LogFilePath $LogFile -Message "[WARNING] Could not retrieve motherboard information: $($_.Exception.Message)"
        }
        
        $oemInfo = [PSCustomObject]@{
            Manufacturer = $manufacturer
            NormalizedManufacturer = $normalizedManufacturer
            Model = $model
        }
        
        Write-ScriptLog -LogFilePath $LogFile -Message "--- OEM Detection Summary ---"
        Write-ScriptLog -LogFilePath $LogFile -Message "Original Manufacturer: $manufacturer"
        Write-ScriptLog -LogFilePath $LogFile -Message "Normalized Manufacturer: $normalizedManufacturer"
        Write-ScriptLog -LogFilePath $LogFile -Message "Model: $model"
        Write-ScriptLog -LogFilePath $LogFile -Message "=== OEM Hardware Information Detection Complete ==="
        
        return $oemInfo
        
    } catch {
        Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] Failed to retrieve OEM hardware information"
        Write-ScriptLog -LogFilePath $LogFile -Message "Error Type: $($_.Exception.GetType().FullName)"
        Write-ScriptLog -LogFilePath $LogFile -Message "Error Message: $($_.Exception.Message)"
        
        # Return fallback values
        $fallbackResult = [PSCustomObject]@{
            Manufacturer = "Unknown"
            NormalizedManufacturer = "Unknown"
            Model = "Unknown"
        }
        
        Write-ScriptLog -LogFilePath $LogFile -Message "[FALLBACK] Using unknown values for OEM information"
        Write-ScriptLog -LogFilePath $LogFile -Message "=== OEM Hardware Information Detection Failed ==="
        
        return $fallbackResult
    }
}


function Get-DownloadPath {
    param (
        [string]$LocalDownloadPath,
        [string]$RemoteDownloadPath,
        [string]$DefaultDownloadPath
    )

    $localSubnets = @(
        "10.0.0","10.0.1","10.0.2","10.0.3",
        "10.0.4","10.0.5","10.0.6","10.0.7"
    )

    $remoteSubnets = @(
        "192.168.1","192.168.2","192.168.3","192.168.4",
        "192.168.5","192.168.6","192.168.7","192.168.8"
    )

    $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
    foreach ($adapter in $adapters) {
        $ipAddresses = (Get-NetIPAddress -InterfaceIndex $adapter.IfIndex).IPAddress | Where-Object { $_ -match "^\d+\.\d+\.\d+\.\d+$" }
        foreach ($ip in $ipAddresses) {
            $subnet = $ip.Split(".")[0..2] -join "."
            if ($localSubnets -contains $subnet) {
                Write-ScriptLog -LogFilePath $LogFile -Message "Local subnet detected: $subnet"
                [PSCustomObject]@{
                    Path = $LocalDownloadPath
                    Type = "Local"
                }
                return
            }
            if ($remoteSubnets -contains $subnet) {
                Write-ScriptLog -LogFilePath $LogFile -Message "Remote subnet detected: $subnet"
                [PSCustomObject]@{
                    Path = $RemoteDownloadPath
                    Type = "Remote"
                }
                return
            }
        }
    }
    Write-ScriptLog -LogFilePath $LogFile -Message "No specific subnet detected, using default download path."
    [PSCustomObject]@{
        Path = $DefaultDownloadPath
        Type = "Default"
    }
}


function Get-FileFromShare {
    param (
        [Parameter(Mandatory)]
        [string]$SharePath,
        
        [Parameter(Mandatory)]
        [string]$FileName,
        
        [string]$DestinationPath
    )
    
    try {
        $sourceFile = Join-Path -Path $SharePath -ChildPath $FileName
        $destinationFile = Join-Path -Path $DestinationPath -ChildPath $FileName
        
        if (-not (Test-Path -Path $sourceFile)) {
            Write-ScriptLog -LogFilePath $LogFile -Message "Download failed: Source file does not exist - $sourceFile"
            return $false
        }
        
        if (Test-Path -Path $destinationFile) {
            Remove-Item -Path $destinationFile -Force
        }
        
        Copy-Item -Path $sourceFile -Destination $destinationFile -Force
        
        if (Test-Path -Path $destinationFile) {
            Write-ScriptLog -LogFilePath $LogFile -Message "File downloaded successfully - $destinationFile"
            return $true
        } else {
            Write-ScriptLog -LogFilePath $LogFile -Message "File download failed - $destinationFile"
            return $false
        }
    }
    catch {
        Write-ScriptLog -LogFilePath $LogFile -Message "Error downloading file - $($_.Exception.Message)"
        return $false
    }
}


function Get-FileFromUrl {
    param (
        [Parameter(Mandatory)]
        [string]$DownloadUrl,
        
        [string]$DestinationPath,
        
        [string]$FileName = ""
    )
    
    Write-ScriptLog -LogFilePath $LogFile -Message "=== Starting File Download from URL ==="
    Write-ScriptLog -LogFilePath $LogFile -Message "Source URL: $DownloadUrl"
    Write-ScriptLog -LogFilePath $LogFile -Message "Destination Path: $DestinationPath"
    
    try {
        # Validate URL format
        try {
            $uri = [System.Uri]::new($DownloadUrl)
            Write-ScriptLog -LogFilePath $LogFile -Message "[VALIDATION] URL format is valid"
            Write-ScriptLog -LogFilePath $LogFile -Message "Protocol: $($uri.Scheme)"
            Write-ScriptLog -LogFilePath $LogFile -Message "Host: $($uri.Host)"
        } catch {
            Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] Invalid URL format: $DownloadUrl"
            Write-ScriptLog -LogFilePath $LogFile -Message "=== File Download from URL Failed ==="
            return @{ Success = $false; Error = "Invalid URL format: $DownloadUrl" }
        }
        
        # Determine file name
        if ([string]::IsNullOrEmpty($FileName)) {
            $FileName = [System.IO.Path]::GetFileName($DownloadUrl)
            Write-ScriptLog -LogFilePath $LogFile -Message "[INFO] Auto-detected file name: $FileName"
        } else {
            Write-ScriptLog -LogFilePath $LogFile -Message "[INFO] Using provided file name: $FileName"
        }
        
        # Prepare destination path
        Write-ScriptLog -LogFilePath $LogFile -Message "[STEP 1] Preparing destination directory..."
        if (-not (Test-Path -Path $DestinationPath)) {
            try {
                New-Item -Path $DestinationPath -ItemType Directory -Force | Out-Null
                Write-ScriptLog -LogFilePath $LogFile -Message "[SUCCESS] Destination directory created: $DestinationPath"
            } catch {
                Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] Failed to create destination directory: $($_.Exception.Message)"
                Write-ScriptLog -LogFilePath $LogFile -Message "=== File Download from URL Failed ==="
                return @{ Success = $false; Error = "Failed to create destination directory: $($_.Exception.Message)" }
            }
        } else {
            Write-ScriptLog -LogFilePath $LogFile -Message "[INFO] Destination directory already exists"
        }
        
        $destinationFile = Join-Path -Path $DestinationPath -ChildPath $FileName
        Write-ScriptLog -LogFilePath $LogFile -Message "Full destination path: $destinationFile"
        
        # Handle existing file
        if (Test-Path -Path $destinationFile) {
            $existingFile = Get-Item $destinationFile
            Write-ScriptLog -LogFilePath $LogFile -Message "[INFO] Existing file found - Size: $([math]::Round($existingFile.Length/1MB, 2)) MB, Modified: $($existingFile.LastWriteTime)"
            
            try {
                Remove-Item -Path $destinationFile -Force
                Write-ScriptLog -LogFilePath $LogFile -Message "[SUCCESS] Existing file removed successfully"
            } catch {
                Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] Failed to remove existing file: $($_.Exception.Message)"
                Write-ScriptLog -LogFilePath $LogFile -Message "=== File Download from URL Failed ==="
                return @{ Success = $false; Error = "Failed to remove existing file: $($_.Exception.Message)" }
            }
        }
        
        # Start download
        Write-ScriptLog -LogFilePath $LogFile -Message "[STEP 2] Starting file download..."
        Write-ScriptLog -LogFilePath $LogFile -Message "Download timeout: 300 seconds"
        
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        
        Invoke-WebRequest -Uri $DownloadUrl -OutFile $destinationFile -TimeoutSec 300 -UseBasicParsing
        
        $stopwatch.Stop()
        
        # Verify download success
        if (Test-Path -Path $destinationFile) {
            $downloadedFile = Get-Item $destinationFile
            $fileSizeMB = [math]::Round($downloadedFile.Length/1MB, 2)
            $downloadSpeed = if ($stopwatch.Elapsed.TotalSeconds -gt 0) { [math]::Round($fileSizeMB / $stopwatch.Elapsed.TotalSeconds, 2) } else { 0 }
            
            Write-ScriptLog -LogFilePath $LogFile -Message "[SUCCESS] File downloaded successfully"
            Write-ScriptLog -LogFilePath $LogFile -Message "File Size: $fileSizeMB MB"
            Write-ScriptLog -LogFilePath $LogFile -Message "Download Time: $($stopwatch.Elapsed.TotalSeconds.ToString('F2')) seconds"
            Write-ScriptLog -LogFilePath $LogFile -Message "Average Speed: $downloadSpeed MB/s"
            Write-ScriptLog -LogFilePath $LogFile -Message "Final Path: $destinationFile"
            Write-ScriptLog -LogFilePath $LogFile -Message "=== File Download from URL Complete ==="
            
            return @{ Success = $true; FilePath = $destinationFile; FileSize = $fileSizeMB; DownloadTime = $stopwatch.Elapsed.TotalSeconds }
        } else {
            Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] Download completed but file not found at destination"
            Write-ScriptLog -LogFilePath $LogFile -Message "=== File Download from URL Failed ==="
            return @{ Success = $false; Error = "Download completed but file not found at destination" }
        }
        
    } catch {
        Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] Exception occurred during file download"
        Write-ScriptLog -LogFilePath $LogFile -Message "Error Type: $($_.Exception.GetType().FullName)"
        Write-ScriptLog -LogFilePath $LogFile -Message "Error Message: $($_.Exception.Message)"
        
        if ($_.Exception.Response) {
            Write-ScriptLog -LogFilePath $LogFile -Message "HTTP Status: $($_.Exception.Response.StatusCode) $($_.Exception.Response.StatusDescription)"
        }
        
        if ($_.Exception.InnerException) {
            Write-ScriptLog -LogFilePath $LogFile -Message "Inner Exception: $($_.Exception.InnerException.Message)"
        }
        
        Write-ScriptLog -LogFilePath $LogFile -Message "=== File Download from URL Failed ==="
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}


function Sync-SharedFiles {
    param(
        [Parameter(Mandatory)]
        [string]$SharePath,  

        [Parameter(Mandatory)]
        [string[]]$FileList,  

        [Parameter()]
        [string]$LocalFolder  
    )

    Write-ScriptLog -LogFilePath $LogFile -Message "Starting Sync-SharedFiles operation"
    Write-ScriptLog -LogFilePath $LogFile -Message "SharePath: $SharePath"
    Write-ScriptLog -LogFilePath $LogFile -Message "LocalFolder: $LocalFolder"
    Write-ScriptLog -LogFilePath $LogFile -Message "FileList: $($FileList -join ', ')"

    # Validate SharePath exists
    if (-not (Test-Path -Path $SharePath)) {
        Write-ScriptLog -LogFilePath $LogFile -Message "ERROR: SharePath does not exist: $SharePath"
        return @{ Success = $false; Missing = $FileList; Error = "SharePath not found: $SharePath" }
    }

    if (-not (Test-Path -Path $LocalFolder)) {
        Write-ScriptLog -LogFilePath $LogFile -Message "Creating local cache directory: $LocalFolder"
        try {
            New-Item -ItemType Directory -Path $LocalFolder -Force | Out-Null
        }
        catch {
            Write-ScriptLog -LogFilePath $LogFile -Message "ERROR: Failed to create local directory: $($_.Exception.Message)"
            return @{ Success = $false; Missing = $FileList; Error = "Failed to create local directory: $($_.Exception.Message)" }
        }
    }

    $missingFiles = @()
    $processedFiles = 0

    foreach ($file in $FileList) {
        $processedFiles++
        Write-ScriptLog -LogFilePath $LogFile -Message "Processing file $processedFiles/$($FileList.Count): $file"
        
        $localFile = Join-Path $LocalFolder $file
        $shareFile = Join-Path $SharePath $file

        $needDownload = $false

        # Check if share file exists first
        if (-not (Test-Path -Path $shareFile)) {
            Write-ScriptLog -LogFilePath $LogFile -Message "WARNING: Source file not found in share: $shareFile"
            $missingFiles += $file
            continue
        }

        if (-not (Test-Path $localFile)) {
            Write-ScriptLog -LogFilePath $LogFile -Message "Missing file: $file"
            $needDownload = $true
        }
        else {
            try {
                $localHash = Get-FileHash -Path $localFile -Algorithm SHA256
                $shareHash = Get-FileHash -Path $shareFile -Algorithm SHA256

                if ($localHash.Hash -ne $shareHash.Hash) {
                    Write-ScriptLog -LogFilePath $LogFile -Message "File mismatch, needs update: $file"
                    $needDownload = $true
                }
                else {
                    Write-ScriptLog -LogFilePath $LogFile -Message "File exists and is valid: $file"
                }
            }
            catch {
                Write-ScriptLog -LogFilePath $LogFile -Message "ERROR: Failed to calculate hash for $file - $($_.Exception.Message)"
                $needDownload = $true
            }
        }

        if ($needDownload) {
            try {
                $downloadResult = Get-FileFromShare -SharePath $SharePath -FileName $file -DestinationPath $LocalFolder
                if ($downloadResult -eq $true) {
                    Write-ScriptLog -LogFilePath $LogFile -Message "Download successfully: $file"
                } else {
                    Write-ScriptLog -LogFilePath $LogFile -Message "Download failed: $file - Get-FileFromShare returned false"
                    $missingFiles += $file
                }
            }
            catch {
                Write-ScriptLog -LogFilePath $LogFile -Message "Download failed: $file - Exception: $($_.Exception.Message)"
                $missingFiles += $file
            }
        }
    }

    Write-ScriptLog -LogFilePath $LogFile -Message "Sync-SharedFiles operation completed"
    Write-ScriptLog -LogFilePath $LogFile -Message "Total files processed: $($FileList.Count)"
    Write-ScriptLog -LogFilePath $LogFile -Message "Files requiring download: $($FileList.Count - ($FileList.Count - $processedFiles + $missingFiles.Count))"
    Write-ScriptLog -LogFilePath $LogFile -Message "Missing/failed files: $($missingFiles.Count)"

    if ($missingFiles.Count -eq 0) {
        Write-ScriptLog -LogFilePath $LogFile -Message "All files synchronized successfully"
        return @{ Success = $true; Path = $LocalFolder }
    }
    else {
        Write-ScriptLog -LogFilePath $LogFile -Message "Some files failed to synchronize: $($missingFiles -join ', ')"
        return @{ Success = $false; Missing = $missingFiles }
    }
}


function Invoke-ExternalCommand {
    param(
        [Parameter(Mandatory=$true)]
        [string]$WorkingDirectory,

        [Parameter(Mandatory=$true)]
        [string]$Command,

        [int]$TimeoutSeconds = 0
    )

    try {
        $fullCommand = "cd /d`"$WorkingDirectory`" && $Command"

        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = New-Object System.Diagnostics.ProcessStartInfo
        $process.StartInfo.FileName = "cmd.exe"
        $process.StartInfo.Arguments = "/c $fullCommand"
        $process.StartInfo.Verb = "runas"   
        $process.StartInfo.RedirectStandardOutput = $true
        $process.StartInfo.RedirectStandardError  = $true
        $process.StartInfo.UseShellExecute = $false
        $process.StartInfo.CreateNoWindow = $true

        # Derive an effective timeout: shorter for HTA/UI commands, longer for others
        $effectiveTimeout = if ($TimeoutSeconds -gt 0) { $TimeoutSeconds } elseif ($Command -match '\.hta(\s|$)') { 120 } else { 600 }

        Write-ScriptLog -LogFilePath $LogFile -Message "Executing command: $Command in directory: $WorkingDirectory"
        if ($Command -match '\.hta(\s|$)') {
            Write-ScriptLog -LogFilePath $LogFile -Message "Detected HTA command; applying $effectiveTimeout seconds timeout to prevent hangs"
        }
        
        $process.Start() | Out-Null

        # Wait with timeout to avoid indefinite hangs (e.g., interactive HTA)
        $exited = $process.WaitForExit($effectiveTimeout * 1000)
        if (-not $exited) {
            Write-ScriptLog -LogFilePath $LogFile -Message "Command timeout after $effectiveTimeout seconds: $Command"
            # Do not kill the process to avoid side effects; just report failure and continue.
            return $false
        }

        # Only read streams after confirmed exit to avoid ReadToEnd blocking
        $stdOut = $process.StandardOutput.ReadToEnd()
        $stdErr = $process.StandardError.ReadToEnd()
        $exitCode = $process.ExitCode

        if ($stdOut) {
            Write-ScriptLog -LogFilePath $LogFile -Message "Command output: $stdOut"
        }
        if ($stdErr) {
            Write-ScriptLog -LogFilePath $LogFile -Message "Command error: $stdErr"
        }

        Write-ScriptLog -LogFilePath $LogFile -Message "Command exit code: $exitCode"

        if ($exitCode -eq 0) {
            return $true
        } else {
            return $false
        }
    }
    catch {
        Write-ScriptLog -LogFilePath $LogFile -Message "Exception while executing command: $_"
        return $false
    }
}


# Helper: Wait until OS drive (C:) is protected (ProtectionStatus = On)
function Wait-ForOSBitLockerProtection {
    param(
        [int]$PollSeconds = 30,
        [int]$MaxWaitSeconds = 0  # 0 = wait indefinitely
    )

    Write-ScriptLog -LogFilePath $LogFile -Message "[AUTO-UNLOCK PRECHECK] Waiting for OS drive C: to be protected (ProtectionStatus=On)"
    $elapsed = 0
    while ($true) {
        try {
            $os = Get-BitLockerVolume -MountPoint 'C:' -ErrorAction SilentlyContinue
            if ($os -and $os.ProtectionStatus -eq 'On') {
                Write-ScriptLog -LogFilePath $LogFile -Message "[AUTO-UNLOCK PRECHECK] OS drive C: is protected; proceeding with data drive Auto-Unlock"
                return $true
            } else {
                $prot = if ($os) { $os.ProtectionStatus } else { 'Unknown' }
                $vs   = if ($os) { $os.VolumeStatus } else { 'Unknown' }
                Write-ScriptLog -LogFilePath $LogFile -Message "[AUTO-UNLOCK PRECHECK] OS not ready (Protection=$prot, VolumeStatus=$vs). Rechecking in ${PollSeconds}s"
            }
        } catch {
            Write-ScriptLog -LogFilePath $LogFile -Message "[AUTO-UNLOCK PRECHECK] Query OS protection failed: $($_.Exception.Message). Rechecking in ${PollSeconds}s"
        }

        Start-Sleep -Seconds $PollSeconds
        $elapsed += $PollSeconds
        if ($MaxWaitSeconds -gt 0 -and $elapsed -ge $MaxWaitSeconds) {
            Write-ScriptLog -LogFilePath $LogFile -Message "[AUTO-UNLOCK PRECHECK] Timeout after ${MaxWaitSeconds}s waiting for OS protection"
            return $false
        }
    }
}

# Helper: Unlock data drive with recovery password if locked
function Unlock-DataDriveIfLocked {
    param(
        [Parameter(Mandatory=$true)]
        [string]$MountPoint,
        [string]$RecoveryKeyPath = "$env:SystemDrive\BitLockerRecoveryKeys"
    )

    $normalized = $MountPoint.TrimEnd(':') + ':'
    if ($normalized -eq 'C:') { return $true }

    try {
        $vol = Get-BitLockerVolume -MountPoint $normalized -ErrorAction SilentlyContinue
        if ($vol -and ($vol.LockStatus -eq 'Unlocked' -or $vol.ProtectionStatus -eq 'On')) {
            return $true
        }
    } catch { }

    # If we reached here, volume may be locked or status unavailable
    Write-ScriptLog -LogFilePath $LogFile -Message "[UNLOCK PRECHECK] Data drive $normalized appears locked or status unavailable; attempting unlock"

    try {
        $driveLetter = $normalized.TrimEnd(':')
        $recoveryFile = Join-Path $RecoveryKeyPath ("$driveLetter-RecoveryKey.txt")
        if (-not (Test-Path $recoveryFile)) {
            Write-ScriptLog -LogFilePath $LogFile -Message "[UNLOCK WARNING] Recovery key file not found for $normalized at $recoveryFile"
            return $false
        }

        # Parse recovery password from file
        $content = Get-Content -Path $recoveryFile -ErrorAction Stop
        $Recoverypwd = ($content | Where-Object { $_ -match '^\s*Recovery\s+Password\s*:\s*([0-9\-]+)\s*$' } | ForEach-Object { ($_ -replace '^.*:\s*','').Trim() }) | Select-Object -First 1
        if (-not $Recoverypwd) {
            Write-ScriptLog -LogFilePath $LogFile -Message "[UNLOCK ERROR] Could not parse recovery password from $recoveryFile"
            return $false
        }

        Write-ScriptLog -LogFilePath $LogFile -Message "[UNLOCK] Using recovery password to unlock $normalized"
        $unlockCmd = "manage-bde -unlock $normalized -RecoveryPassword $Recoverypwd"
        $proc = Start-Process -FilePath "powershell" -ArgumentList "-NoProfile","-NonInteractive","-Command", $unlockCmd -Wait -PassThru -WindowStyle Hidden -ErrorAction SilentlyContinue
        if ($proc -and $proc.ExitCode -eq 0) {
            Start-Sleep -Seconds 2
            $verify = Get-BitLockerVolume -MountPoint $normalized -ErrorAction SilentlyContinue
            if ($verify -and $verify.LockStatus -eq 'Unlocked') {
                Write-ScriptLog -LogFilePath $LogFile -Message "[UNLOCK SUCCESS] Drive $normalized unlocked"
                return $true
            }
        }
        Write-ScriptLog -LogFilePath $LogFile -Message "[UNLOCK FAILED] Unable to unlock $normalized (ExitCode=$($proc.ExitCode))"
        return $false
    } catch {
        Write-ScriptLog -LogFilePath $LogFile -Message "[UNLOCK ERROR] Unlock attempt failed for $normalized : $($_.Exception.Message)"
        return $false
    }
}

# Helper: Force status refresh via manage-bde and parse key fields
function Get-ManageBdeStatusInfo {
    param(
        [Parameter(Mandatory=$true)]
        [string]$MountPoint,
        [Parameter(Mandatory=$true)]
        [string]$LogFile
    )

    $normalized = $MountPoint.TrimEnd(':') + ':'
    try {
        Write-ScriptLog -LogFilePath $LogFile -Message "[REFRESH] Forcing BitLocker status refresh via manage-bde for $normalized"
        $outputLines = (& manage-bde -status $normalized) 2>&1
        $output = ($outputLines | Out-String)
        if ($output) {
            # Parse percentage encrypted if available
            $percent = $null
            if ($output -match 'Percentage\s+Encrypted:\s+(\d+)\s*%') {
                $percent = [int]$Matches[1]
                Write-ScriptLog -LogFilePath $LogFile -Message "[REFRESH RESULT] $normalized encryption detected at ${percent}%"
            } elseif ($output -match '已加密百分比:\s*(\d+)\s*%') {
                $percent = [int]$Matches[1]
                Write-ScriptLog -LogFilePath $LogFile -Message "[REFRESH RESULT] $normalized encryption detected (CN) at ${percent}%"
            } else {
                Write-ScriptLog -LogFilePath $LogFile -Message "[REFRESH RESULT] No percentage found for $normalized"
            }

            # Optionally parse lock status
            $lock = $null
            if ($output -match 'Lock\s+Status:\s*([^\r\n]+)') {
                $lock = ($Matches[1]).Trim()
                Write-ScriptLog -LogFilePath $LogFile -Message "[REFRESH RESULT] $normalized lock status: $lock"
            } elseif ($output -match '锁定状态:\s*([^\r\n]+)') {
                $lock = ($Matches[1]).Trim()
                Write-ScriptLog -LogFilePath $LogFile -Message "[REFRESH RESULT] $normalized lock status (CN): $lock"
            }

            # Parse additional fields: Protection/Conversion/Auto-Unlock/Encryption Method/Version (EN+CN)
            $protection = $null
            if ($output -match 'Protection\s+Status:\s*([^\r\n]+)') { $protection = ($Matches[1]).Trim() }
            elseif ($output -match '保护状态:\s*([^\r\n]+)') { $protection = ($Matches[1]).Trim() }
            if ($protection) { Write-ScriptLog -LogFilePath $LogFile -Message "[REFRESH RESULT] $normalized protection status: $protection" }

            $conversion = $null
            if ($output -match 'Conversion\s+Status:\s*([^\r\n]+)') { $conversion = ($Matches[1]).Trim() }
            elseif ($output -match '转换状态:\s*([^\r\n]+)') { $conversion = ($Matches[1]).Trim() }
            if ($conversion) { Write-ScriptLog -LogFilePath $LogFile -Message "[REFRESH RESULT] $normalized conversion status: $conversion" }

            $autoUnlock = $null
            if ($output -match 'Auto\s*-?\s*Unlock:\s*([^\r\n]+)') { $autoUnlock = ($Matches[1]).Trim() }
            elseif ($output -match '自动解锁:\s*([^\r\n]+)') { $autoUnlock = ($Matches[1]).Trim() }
            if ($autoUnlock) { Write-ScriptLog -LogFilePath $LogFile -Message "[REFRESH RESULT] $normalized auto-unlock: $autoUnlock" }

            $encMethod = $null
            if ($output -match 'Encryption\s+Method:\s*([^\r\n]+)') { $encMethod = ($Matches[1]).Trim() }
            elseif ($output -match '加密方法:\s*([^\r\n]+)') { $encMethod = ($Matches[1]).Trim() }
            if ($encMethod) { Write-ScriptLog -LogFilePath $LogFile -Message "[REFRESH RESULT] $normalized encryption method: $encMethod" }

            $blVersion = $null
            if ($output -match 'BitLocker\s+Version:\s*([^\r\n]+)') { $blVersion = ($Matches[1]).Trim() }
            elseif ($output -match 'BitLocker\s*版本:\s*([^\r\n]+)') { $blVersion = ($Matches[1]).Trim() }
            if ($blVersion) { Write-ScriptLog -LogFilePath $LogFile -Message "[REFRESH RESULT] $normalized BitLocker version: $blVersion" }

            return @{ Raw = $output; PercentageEncrypted = $percent; LockStatus = $lock; ProtectionStatus = $protection; ConversionStatus = $conversion; AutoUnlock = $autoUnlock; EncryptionMethod = $encMethod; BitLockerVersion = $blVersion }
        } else {
            Write-ScriptLog -LogFilePath $LogFile -Message "[REFRESH WARNING] manage-bde returned no output for $normalized"
            return @{ Raw = ''; PercentageEncrypted = $null; LockStatus = $null; ProtectionStatus = $null; ConversionStatus = $null; AutoUnlock = $null; EncryptionMethod = $null; BitLockerVersion = $null }
        }
    } catch {
        Write-ScriptLog -LogFilePath $LogFile -Message "[REFRESH ERROR] manage-bde status failed for $normalized : $($_.Exception.Message)"
        return @{ Raw = ''; PercentageEncrypted = $null; LockStatus = $null; ProtectionStatus = $null; ConversionStatus = $null; AutoUnlock = $null; EncryptionMethod = $null; BitLockerVersion = $null }
    }
}

# Helper: Reset Auto-Unlock (disable then enable) for accessible data drive
function Reset-DataDriveAutoUnlock {
    param(
        [Parameter(Mandatory=$true)]
        [string]$MountPoint,
        [Parameter(Mandatory=$true)]
        [string]$LogFile
    )

    $normalized = $MountPoint.TrimEnd(':') + ':'
    if ($normalized -eq 'C:') {
        Write-ScriptLog -LogFilePath $LogFile -Message "[AUTO-UNLOCK SKIP] System drive $normalized does not require reset"
        return $true
    }

    try {
        # Ensure unlocked before reset
        $unlocked = Unlock-DataDriveIfLocked -MountPoint $normalized
        if (-not $unlocked) {
            Write-ScriptLog -LogFilePath $LogFile -Message "[AUTO-UNLOCK WARNING] $normalized appears locked; reset skipped"
            return $false
        }

        Write-ScriptLog -LogFilePath $LogFile -Message "[AUTO-UNLOCK RESET] Disabling Auto-Unlock for $normalized"
        Disable-BitLockerAutoUnlock -MountPoint $normalized -Confirm:$false -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1

        Write-ScriptLog -LogFilePath $LogFile -Message "[AUTO-UNLOCK RESET] Enabling Auto-Unlock for $normalized"
        try {
            Enable-BitLockerAutoUnlock -MountPoint $normalized -Confirm:$false -ErrorAction Stop
            Start-Sleep -Seconds 2
            $verify = Get-BitLockerVolume -MountPoint $normalized -ErrorAction SilentlyContinue
            if ($verify -and $verify.AutoUnlockEnabled) {
                Write-ScriptLog -LogFilePath $LogFile -Message "[AUTO-UNLOCK RECOVERED] Auto-Unlock re-enabled for $normalized"
                return $true
            } else {
                Write-ScriptLog -LogFilePath $LogFile -Message "[AUTO-UNLOCK WARNING] Reset executed but verification failed for $normalized"
                return $false
            }
        } catch {
            Write-ScriptLog -LogFilePath $LogFile -Message "[AUTO-UNLOCK ERROR] Failed to reset Auto-Unlock for $normalized : $($_.Exception.Message)"
            return $false
        }
    } catch {
        Write-ScriptLog -LogFilePath $LogFile -Message "[AUTO-UNLOCK ERROR] Reset precheck failed for $normalized : $($_.Exception.Message)"
        return $false
    }
}

# Helper: Enable Auto-Unlock for a data drive after ensuring OS drive is protected
function Enable-DataDriveAutoUnlock {
    param(
        [Parameter(Mandatory=$true)]
        [string]$MountPoint
    )

    if ($MountPoint -eq 'C:') {
        Write-ScriptLog -LogFilePath $LogFile -Message "[AUTO-UNLOCK SKIP] System drive $MountPoint does not require Auto-Unlock"
        return $true
    }

    # Ensure drive is unlocked before proceeding
    $unlocked = Unlock-DataDriveIfLocked -MountPoint $MountPoint
    if (-not $unlocked) {
        Write-ScriptLog -LogFilePath $LogFile -Message "[AUTO-UNLOCK WARNING] Skipping Auto-Unlock because drive $MountPoint is locked and could not be unlocked"
        return $false
    }

    # Wait (indefinitely by default) for OS protection before enabling Auto-Unlock
    $ok = Wait-ForOSBitLockerProtection -PollSeconds 5 -MaxWaitSeconds 0
    if (-not $ok) {
        Write-ScriptLog -LogFilePath $LogFile -Message "[AUTO-UNLOCK WARNING] OS protection not satisfied within timeout; skipping Auto-Unlock for $MountPoint"
        return $false
    }

    Write-ScriptLog -LogFilePath $LogFile -Message "[AUTOUNLOCK] Enabling AutoUnlock for $MountPoint"
    try {
        Enable-BitLockerAutoUnlock -MountPoint $MountPoint -Confirm:$false -ErrorAction Stop
        Start-Sleep -Seconds 3
        $verifyStatus = Get-BitLockerVolume -MountPoint $MountPoint -ErrorAction SilentlyContinue
        if ($verifyStatus -and $verifyStatus.AutoUnlockEnabled) {
            Write-ScriptLog -LogFilePath $LogFile -Message "[SUCCESS] AutoUnlock enabled successfully for $MountPoint"
            return $true
        } else {
            Write-ScriptLog -LogFilePath $LogFile -Message "[WARNING] AutoUnlock command executed but verification failed for $MountPoint"
            return $false
        }
        } catch {
        Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] Failed to enable AutoUnlock for $MountPoint : $($_.Exception.Message)"
        return $false
    }
}


function Watch-BitLockerStatus {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$MountPoint,        

        [Parameter()]
        [ValidateRange(1, 3600)]
        [int]$IntervalSeconds = 30, 
        
        [Parameter()]
        [ValidateRange(60, 604800)] 
        [int]$TimeoutSeconds = 21600, 
        
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$LogFile,

        [Parameter()]
        [ScriptBlock]$OnSuccess,     
        
        [Parameter()]
        [ScriptBlock]$OnTimeout      
    )

    if (-not $LogFile) {
        throw "LogFile parameter is required for monitoring operations"
    }

    if ($MountPoint -notmatch '^[A-Za-z]:?$') {
        throw "Invalid MountPoint format. Expected format: 'C:' or 'C'"
    }

    # Check if running in non-interactive mode (GPO scheduled task environment)
    $isNonInteractive = $false
    try {
        $isNonInteractive = -not [Environment]::UserInteractive -or 
                           (Get-Process -Id $PID).SessionId -eq 0 -or
                           $env:SESSIONNAME -eq "Console" -or
                           [string]::IsNullOrEmpty($env:USERNAME)
    } catch {
        # If we can't determine the session type, assume non-interactive for safety
        $isNonInteractive = $true
    }

    if ($isNonInteractive) {
        Write-ScriptLog -LogFilePath $LogFile -Message "[MONITOR MODE] Running in non-interactive mode (GPO/Service context) - callback functions will be skipped"
        # Clear callback parameters to prevent any potential user interaction
        $OnSuccess = $null
        $OnTimeout = $null
    }

    $normalizedMountPoint = $MountPoint.TrimEnd(':') + ':'
    
    # Check if this is the system drive
    $isSystemDrive = ($normalizedMountPoint -eq "C:")
    
    if ($isSystemDrive) {
        Write-ScriptLog -LogFilePath $LogFile -Message "[MONITOR SKIP] System drive $normalizedMountPoint does not require monitoring - BitLocker will auto-unlock during boot"
        return $true
    }

    Write-ScriptLog -LogFilePath $LogFile -Message "[MONITOR START] Starting BitLocker status monitoring for data drive $normalizedMountPoint"
    Write-ScriptLog -LogFilePath $LogFile -Message "[MONITOR CONFIG] Interval: ${IntervalSeconds}s, Timeout: ${TimeoutSeconds}s"

    $startTime = Get-Date
    $iterationCount = 0
    
    while ($true) {
        $iterationCount++
        
        try {
            if (-not (Test-Path $normalizedMountPoint)) {
                throw "Mount point $normalizedMountPoint does not exist or is not accessible"
            }

            $result = Get-BitLockerVolume -MountPoint $normalizedMountPoint -ErrorAction Stop

            if ($null -ne $result) {
                $enc  = $result.EncryptionPercentage
                $prot = $result.ProtectionStatus
                $stat = $result.VolumeStatus

                Write-ScriptLog -LogFilePath $LogFile -Message "[MONITOR #$iterationCount] Disk ${normalizedMountPoint} - Status: ${stat} - Encryption: ${enc}% - Protection: ${prot}"

                # Handle Unknown status with layered probing
                if ($stat -eq 'Unknown' -or ($enc -eq 0 -and $null -eq $prot)) {
                    Write-ScriptLog -LogFilePath $LogFile -Message "[NOTICE] $normalizedMountPoint status Unknown — waiting for BitLocker service to refresh..."
                    Start-Sleep -Seconds 10
                    try {
                        $result = Get-BitLockerVolume -MountPoint $normalizedMountPoint -ErrorAction SilentlyContinue
                        if ($result) {
                            $enc  = $result.EncryptionPercentage
                            $prot = $result.ProtectionStatus
                            $stat = $result.VolumeStatus
                            Write-ScriptLog -LogFilePath $LogFile -Message "[NOTICE] Recheck after wait: Status=$stat, Encryption=$enc%, Protection=$prot"
                        }
                    } catch {}

                    if ($stat -eq 'Unknown') {
                        $refresh = Get-ManageBdeStatusInfo -MountPoint $normalizedMountPoint -LogFile $LogFile

                        # Overlay encryption percentage and protection status from manage-bde when available
                        if ($null -ne $refresh.PercentageEncrypted) {
                            $enc = $refresh.PercentageEncrypted
                            Write-ScriptLog -LogFilePath $LogFile -Message "[REFRESH INFO] manage-bde indicates $enc% encrypted for $normalizedMountPoint"
                        }
                        if ($refresh.ProtectionStatus) {
                            $prot = $refresh.ProtectionStatus
                            Write-ScriptLog -LogFilePath $LogFile -Message "[REFRESH INFO] manage-bde protection status: $prot"
                        }
                        if ($refresh.ConversionStatus) {
                            Write-ScriptLog -LogFilePath $LogFile -Message "[REFRESH INFO] manage-bde conversion status: $($refresh.ConversionStatus)"
                        }

                        $lockStatus = $refresh.LockStatus
                        $auto = $refresh.AutoUnlock

                        # If manage-bde indicates the volume is locked, classify as Locked-Unknown and skip Auto-Unlock reset
                        if ($lockStatus -and ($lockStatus -match 'Locked' -or $lockStatus -match '已锁定')) {
                            Write-ScriptLog -LogFilePath $LogFile -Message "[LOCKED-UNKNOWN] $normalizedMountPoint is locked (manage-bde: $lockStatus); skipping Auto-Unlock reset"
                        }
                        else {
                            # Only attempt Auto-Unlock reset when path is accessible and auto-unlock is disabled
                            $pathAccessible = $false
                            try {
                                $pathAccessible = Test-Path (Join-Path $normalizedMountPoint '\\') -ErrorAction SilentlyContinue
                            } catch { $pathAccessible = Test-Path "$normalizedMountPoint\" -ErrorAction SilentlyContinue }

                            if ($pathAccessible -and $auto -and ($auto -match 'Disabled' -or $auto -match '已禁用')) {
                                Write-ScriptLog -LogFilePath $LogFile -Message "[AUTO-UNLOCK] $normalizedMountPoint accessible & auto-unlock disabled — resetting"
                                [void](Reset-DataDriveAutoUnlock -MountPoint $normalizedMountPoint -LogFile $LogFile)
                            }
                        }
                    }
                }

                if ($enc -eq 100 -and $prot.ToString() -eq "On") {
                    $elapsedTime = (Get-Date) - $startTime
                    Write-ScriptLog -LogFilePath $LogFile -Message "[MONITOR SUCCESS] Disk ${normalizedMountPoint} encryption completed and protection is On (Elapsed: $($elapsedTime.ToString('hh\:mm\:ss')))"
                    
                    # Enable Auto-Unlock immediately for data drives only (wait for OS protection first)
                    if ($normalizedMountPoint -ne "C:") {
                        Write-ScriptLog -LogFilePath $LogFile -Message "[AUTO-UNLOCK] Attempting to enable Auto-Unlock for data drive ${normalizedMountPoint}"
                        $enabled = Enable-DataDriveAutoUnlock -MountPoint $normalizedMountPoint
                        if ($enabled) {
                            Write-ScriptLog -LogFilePath $LogFile -Message "[AUTO-UNLOCK SUCCESS] Auto-Unlock enabled for data drive ${normalizedMountPoint}"
                        } else {
                            Write-ScriptLog -LogFilePath $LogFile -Message "[AUTO-UNLOCK WARNING] Auto-Unlock enable failed for data drive ${normalizedMountPoint}"
                        }
                    } else {
                        Write-ScriptLog -LogFilePath $LogFile -Message "[AUTO-UNLOCK SKIP] System drive ${normalizedMountPoint} does not require Auto-Unlock - will auto-unlock during boot"
                    }
                    
                    # Call OnSuccess callback if provided (for backward compatibility)
                    if ($OnSuccess) { 
                        try {
                            Write-ScriptLog -LogFilePath $LogFile -Message "[MONITOR CALLBACK] Executing OnSuccess callback for ${normalizedMountPoint}"
                            & $OnSuccess $normalizedMountPoint $LogFile
                        } catch {
                            Write-ScriptLog -LogFilePath $LogFile -Message "[MONITOR WARNING] OnSuccess callback failed: $($_.Exception.Message)"
                            # Log additional details for debugging
                            if ($_.Exception.InnerException) {
                                Write-ScriptLog -LogFilePath $LogFile -Message "[MONITOR WARNING] OnSuccess callback inner exception: $($_.Exception.InnerException.Message)"
                            }
                        }
                    } else {
                        Write-ScriptLog -LogFilePath $LogFile -Message "[MONITOR INFO] No OnSuccess callback provided or callback disabled for non-interactive mode"
                    }
                    return $true
                }
                
                if ($stat -eq "DecryptionInProgress") {
                    Write-ScriptLog -LogFilePath $LogFile -Message "[MONITOR WARNING] Disk ${normalizedMountPoint} is being decrypted, monitoring will continue"
                }
            } else {
                Write-ScriptLog -LogFilePath $LogFile -Message "[MONITOR WARNING] No BitLocker volume information found for ${normalizedMountPoint}"
            }
        } catch [Microsoft.BitLocker.Structures.BitLockerVolumeException] {
            Write-ScriptLog -LogFilePath $LogFile -Message "[MONITOR ERROR] BitLocker volume error for ${normalizedMountPoint}: $($_.Exception.Message)"
            # Attempt unlock if drive may be locked
            $attempt = Unlock-DataDriveIfLocked -MountPoint $normalizedMountPoint
            if ($attempt) {
                Write-ScriptLog -LogFilePath $LogFile -Message "[MONITOR INFO] Unlock successful; will recheck status on next iteration"
            }
        } catch {
            Write-ScriptLog -LogFilePath $LogFile -Message "[MONITOR ERROR] Unexpected error watching disk ${normalizedMountPoint}: $($_.Exception.Message)"
            Write-ScriptLog -LogFilePath $LogFile -Message "[MONITOR ERROR] Error Type: $($_.Exception.GetType().FullName)"
            # Attempt unlock if drive may be locked
            $attempt = Unlock-DataDriveIfLocked -MountPoint $normalizedMountPoint
            if ($attempt) {
                Write-ScriptLog -LogFilePath $LogFile -Message "[MONITOR INFO] Unlock successful; will recheck status on next iteration"
            }
        }

        $elapsedTime = (Get-Date) - $startTime
        if ($elapsedTime.TotalSeconds -gt $TimeoutSeconds) {
            $timeoutLimit = [TimeSpan]::FromSeconds($TimeoutSeconds)
            Write-ScriptLog -LogFilePath $LogFile -Message "[MONITOR TIMEOUT] Monitoring timeout for disk ${normalizedMountPoint}: $($elapsedTime.ToString('hh\:mm\:ss')) elapsed (limit: $($timeoutLimit.ToString('hh\:mm\:ss')))"
            
            # Call OnTimeout callback if provided (for backward compatibility)
            if ($OnTimeout) { 
                try {
                    Write-ScriptLog -LogFilePath $LogFile -Message "[MONITOR CALLBACK] Executing OnTimeout callback for ${normalizedMountPoint}"
                    & $OnTimeout $normalizedMountPoint $LogFile
                } catch {
                    Write-ScriptLog -LogFilePath $LogFile -Message "[MONITOR WARNING] OnTimeout callback failed: $($_.Exception.Message)"
                    # Log additional details for debugging
                    if ($_.Exception.InnerException) {
                        Write-ScriptLog -LogFilePath $LogFile -Message "[MONITOR WARNING] OnTimeout callback inner exception: $($_.Exception.InnerException.Message)"
                    }
                }
            } else {
                Write-ScriptLog -LogFilePath $LogFile -Message "[MONITOR INFO] No OnTimeout callback provided or callback disabled for non-interactive mode"
            }
            return $false
        }

        Start-Sleep -Seconds $IntervalSeconds
    }
}


function Enable-UnprotectedDrives {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$UnprotectedDrives,   

        [string]$RecoveryKeyPath = "$env:SystemDrive\BitLockerRecoveryKeys", 
        [string]$LogFile = "$env:SystemDrive\BitLockerEnable.log"
    )

    Write-ScriptLog -LogFilePath $LogFile -Message "=== Starting BitLocker Enablement Process (Job-Based) ==="
    # Prepare actions before enable BitLocker
    #   1.Validate input parameters
    if ($null -eq $UnprotectedDrives -or $UnprotectedDrives.Count -eq 0) {
        Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] No drives provided for BitLocker enablement"
        return @()
    }
    
    #   2.Filter out empty or null drive entries
    $validDrives = $UnprotectedDrives | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    if ($validDrives.Count -eq 0) {
        Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] No valid drives found after filtering empty entries"
        return @()
    }
    
    Write-ScriptLog -LogFilePath $LogFile -Message "Total drives to process: $($validDrives.Count)"
    Write-ScriptLog -LogFilePath $LogFile -Message "Drives to encrypt: $($validDrives -join ', ')"
    
    #   3.Prepare recovery key directory
    Write-ScriptLog -LogFilePath $LogFile -Message "[STEP 1] Preparing recovery key directory: $RecoveryKeyPath"
    if (-not (Test-Path $RecoveryKeyPath)) {
        try {
            New-Item -ItemType Directory -Path $RecoveryKeyPath -Force | Out-Null
            Write-ScriptLog -LogFilePath $LogFile -Message "[SUCCESS] Recovery key directory created successfully"
        } catch {
            Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] Failed to create recovery key directory: $RecoveryKeyPath. Error: $_"
            Write-ScriptLog -LogFilePath $LogFile -Message "[FALLBACK] Continuing with default system drive for recovery keys"
            $RecoveryKeyPath = "$env:SystemDrive\"
        }
    } else {
        Write-ScriptLog -LogFilePath $LogFile -Message "[INFO] Recovery key directory already exists"
    }

    # Main flow to enable BitLocker on each drive
    $results = @()
    $totalDrives = $validDrives.Count
    $currentDriveIndex = 0
    $bitlockerJobs = @()  # Store BitLocker enablement jobs
    $drivesToMonitor = @()  # Store drives that need monitoring

    foreach ($drive in $validDrives) {
        $currentDriveIndex++
        
        # Normalize drive format (ensure it ends with colon)
        $normalizedDrive = $drive.Trim().TrimEnd(':') + ":"
        
        Write-ScriptLog -LogFilePath $LogFile -Message "--- Processing Drive $currentDriveIndex of $totalDrives ---"
        Write-ScriptLog -LogFilePath $LogFile -Message "[STEP 2.$currentDriveIndex] Starting BitLocker enablement for drive: $normalizedDrive"

        try {
            # Check TPM compatibility before enabling BitLocker
            Write-ScriptLog -LogFilePath $LogFile -Message "[STEP 3.$currentDriveIndex] Checking TPM compatibility for $normalizedDrive"
            try {
                $tpmStatus = Get-Tpm -ErrorAction SilentlyContinue
                if (-not $tpmStatus -or -not $tpmStatus.TpmPresent) {
                    Write-ScriptLog -LogFilePath $LogFile -Message "[WARNING] TPM not present or not accessible on this system"
                }
                elseif (-not $tpmStatus.TpmReady) {
                    Write-ScriptLog -LogFilePath $LogFile -Message "[WARNING] TPM present but not ready (Enabled: $($tpmStatus.TpmEnabled), Activated: $($tpmStatus.TpmActivated))"
                }
                else {
                    Write-ScriptLog -LogFilePath $LogFile -Message "[INFO] TPM is present and ready (Version: $($tpmStatus.TpmVersion))"
                }
            } catch {
                Write-ScriptLog -LogFilePath $LogFile -Message "[WARNING] Unable to check TPM status: $($_.Exception.Message)"
            }
            # Check TPM compatibility before enabling BitLocker

            # Create BitLocker enablement job
            Write-ScriptLog -LogFilePath $LogFile -Message "[STEP 4.$currentDriveIndex] Creating BitLocker enablement job for $normalizedDrive"
            
            $encryptionMethod = "XtsAes256"  # From $SCRIPT_CONSTANTS.BITLOCKER_ENCRYPTION_METHOD
            
            $jobScriptBlock = {
                param($MountPoint, $EncryptionMethod, $LogFile)
                
                # Import required modules in job context
                Import-Module BitLocker -Force -DisableNameChecking
                
                try {
                    # Set comprehensive non-interactive mode for SYSTEM user compatibility
                    $ProgressPreference = 'SilentlyContinue'
                    $WarningPreference = 'SilentlyContinue'
                    $VerbosePreference = 'SilentlyContinue'
                    $DebugPreference = 'SilentlyContinue'
                    $InformationPreference = 'SilentlyContinue'
                    $ErrorActionPreference = 'Stop'
                    
                    # Set environment variables to prevent UI interactions
                    $env:POWERSHELL_TELEMETRY_OPTOUT = "1"
                    $env:DOTNET_CLI_TELEMETRY_OPTOUT = "1"
                    
                    # Additional non-interactive settings for service mode
                    if ([Environment]::UserInteractive -eq $false) {
                        # Running in service mode - apply additional restrictions
                        $Host.UI.RawUI.WindowTitle = "BitLocker Service Mode"
                    }
                    
                    # Enable BitLocker for OS drive using TPM protector
                    # OS volumes require TPM/Startup protector sets; do not mix with RecoveryPasswordProtector in the same call
                    # Enterprise policy: OS drive must use RecoveryPasswordProtector (for AD backup)
                    # Use UsedSpaceOnly and SkipHardwareTest to avoid reboot if policy allows
                        Enable-BitLocker -MountPoint $MountPoint `
                                -RecoveryPasswordProtector `
                                -SkipHardwareTest `
                                -EncryptionMethod $EncryptionMethod `
                                -Confirm:$false `
                                -ErrorAction Stop `
                                -WarningAction SilentlyContinue `
                                -InformationAction SilentlyContinue `
                                -Verbose:$false `
                                -Debug:$false
                    
                    # Verify BitLocker was actually enabled
                    Start-Sleep -Seconds 2  # Brief pause for BitLocker to initialize
                    $verifyStatus = Get-BitLockerVolume -MountPoint $MountPoint -ErrorAction Stop
                    
                    if ($verifyStatus.ProtectionStatus -eq "On" -or $verifyStatus.VolumeStatus -eq "EncryptionInProgress") {
                        # Add a recovery password protector after successful OS BitLocker enablement
                        try {
                            Add-BitLockerKeyProtector -MountPoint $MountPoint -RecoveryPasswordProtector -ErrorAction Stop | Out-Null
                        } catch {
                            # Log as warning in result payload; main process can decide how to surface it
                            $recoveryAddWarning = $_.Exception.Message
                        }
                        # Ensure TPM protector is present for seamless boot (OS uses TPM; RecoveryPassword is for AD backup)
                        $tpmEnsureWarning = $null
                        try {
                            $tpmEnsured = Enable-OsDriveTpmProtector -MountPoint $MountPoint -LogFile $LogFile
                            if (-not $tpmEnsured) { $tpmEnsureWarning = 'TPM protector missing or could not be added' }
                        } catch {
                            $tpmEnsureWarning = $_.Exception.Message
                        }
                        # Return success result as a hashtable
                        return @{
                            Success = $true
                            MountPoint = $MountPoint
                            Message = "BitLocker enabled successfully"
                            ErrorMessage = $null
                            VolumeStatus = $verifyStatus.VolumeStatus
                            ProtectionStatus = $verifyStatus.ProtectionStatus
                            EncryptionPercentage = $verifyStatus.EncryptionPercentage
                            RecoveryProtectorAddedWarning = $recoveryAddWarning
                            TpmProtectorEnsureWarning = $tpmEnsureWarning
                        }
                    } else {
                        # BitLocker command succeeded but protection is not on
                        return @{
                            Success = $false
                            MountPoint = $MountPoint
                            Message = "BitLocker command executed but protection not enabled"
                            ErrorMessage = "Status: $($verifyStatus.VolumeStatus), Protection: $($verifyStatus.ProtectionStatus)"
                            VolumeStatus = $verifyStatus.VolumeStatus
                            ProtectionStatus = $verifyStatus.ProtectionStatus
                        }
                    }
                } catch [System.InvalidOperationException] {
                    # Handle UserInteractive errors specifically
                    if ($_.Exception.Message -like "*UserInteractive*" -or $_.Exception.Message -like "*显示模式对话框*") {
                        # Try alternative approach for service mode
                        try {
                            # Use WMI method as fallback for service mode
                            $volume = Get-WmiObject -Namespace "Root\cimv2\Security\MicrosoftVolumeEncryption" -Class "Win32_EncryptableVolume" | Where-Object { $_.DriveLetter -eq $MountPoint }
                            if ($volume) {
                                $result = $volume.EnableKeyProtectors()
                                if ($result.ReturnValue -eq 0) {
                                    return @{
                                        Success = $true
                                        MountPoint = $MountPoint
                                        Message = "BitLocker enabled via WMI fallback"
                                        ErrorMessage = "UserInteractive error handled via WMI"
                                        IsUserInteractiveWarning = $true
                                    }
                                }
                            }
                        } catch {
                            # WMI fallback also failed
                        }
                        
                        # Return as UserInteractive warning
                        return @{
                            Success = $false
                            MountPoint = $MountPoint
                            Message = "UserInteractive error in service mode"
                            ErrorMessage = "UserInteractive mode error: $($_.Exception.Message)"
                            IsUserInteractiveWarning = $true
                        }
                    } else {
                        # Other InvalidOperationException
                        return @{
                            Success = $false
                            MountPoint = $MountPoint
                            Message = "BitLocker enablement failed"
                            ErrorMessage = $_.Exception.Message
                        }
                    }
                } catch {
                    # Return error result as a hashtable
                    return @{
                        Success = $false
                        MountPoint = $MountPoint
                        Message = "BitLocker enablement failed"
                        ErrorMessage = $_.Exception.Message
                    }
                }
            }
            
            # Start the BitLocker enablement job
            $job = Start-Job -ScriptBlock $jobScriptBlock -ArgumentList $normalizedDrive, $encryptionMethod, $LogFile
            
            # Store job information
            $bitlockerJobs += @{
                Job = $job
                Drive = $normalizedDrive
                StartTime = Get-Date
                DriveIndex = $currentDriveIndex
            }
            
            Write-ScriptLog -LogFilePath $LogFile -Message "[INFO] BitLocker job created for $normalizedDrive (Job ID: $($job.Id))"
            
            # Add diagnostic information for SYSTEM user context
            try {
                Write-ScriptLog -LogFilePath $LogFile -Message "[DEBUG] Job creation diagnostics for $normalizedDrive"
                Write-ScriptLog -LogFilePath $LogFile -Message "[DEBUG] - Job State: $($job.State)"
                Write-ScriptLog -LogFilePath $LogFile -Message "[DEBUG] - Job HasMoreData: $($job.HasMoreData)"
                Write-ScriptLog -LogFilePath $LogFile -Message "[DEBUG] - Job Location: $($job.Location)"
                Write-ScriptLog -LogFilePath $LogFile -Message "[DEBUG] - Current User: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
                Write-ScriptLog -LogFilePath $LogFile -Message "[DEBUG] - PowerShell Session ID: $PID"
                Write-ScriptLog -LogFilePath $LogFile -Message "[DEBUG] - Job Session ID: $($job.Id)"
                
                # Test immediate job access
                $testJobState = Get-Job -Id $job.Id -ErrorAction SilentlyContinue
                if ($testJobState) {
                    Write-ScriptLog -LogFilePath $LogFile -Message "[DEBUG] - Job accessible via Get-Job: Yes (State: $($testJobState.State))"
                } else {
                    Write-ScriptLog -LogFilePath $LogFile -Message "[DEBUG] - Job accessible via Get-Job: No - This may indicate session isolation issues"
                }
            } catch {
                Write-ScriptLog -LogFilePath $LogFile -Message "[WARNING] Job diagnostics failed: $($_.Exception.Message)"
            }
        } catch {
            Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] Failed to create BitLocker job for $normalizedDrive : $($_.Exception.Message)"
            $results += [PSCustomObject]@{
                Drive            = $normalizedDrive
                RecoveryKeyId    = $null
                RecoveryPassword = $null
                Status           = "Failed"
                ErrorMessage     = "Failed to create BitLocker job: $($_.Exception.Message)"
                IsSystemDrive    = ($normalizedDrive -eq "C:")
            }
        }
        
        Write-ScriptLog -LogFilePath $LogFile -Message "--- Drive $currentDriveIndex Job Creation Complete ---"
    }

    # Wait for all BitLocker jobs to complete and process results
    Write-ScriptLog -LogFilePath $LogFile -Message "[STEP 5] Waiting for BitLocker jobs to complete..."
    
    foreach ($jobInfo in $bitlockerJobs) {
        $job = $jobInfo.Job
        $drive = $jobInfo.Drive
        
        Write-ScriptLog -LogFilePath $LogFile -Message "[INFO] Waiting for BitLocker job completion: $drive (Job ID: $($job.Id))"
        
        # Wait for job completion with extended timeout (4 hours for BitLocker enablement)
        # Note: This is only for BitLocker enablement job completion, not encryption completion
        $jobTimeout = 14400  # 4 hours in seconds (BitLocker enablement can take time on some systems)
        Write-ScriptLog -LogFilePath $LogFile -Message "[INFO] Job timeout set to $($jobTimeout/3600) hours for BitLocker enablement"
        
        # Use a loop to monitor job status and provide periodic updates
        $jobStartTime = Get-Date
        $lastStatusUpdate = $jobStartTime
        $statusUpdateInterval = 300  # Update every 5 minutes
        
        do {
            try {
                $jobResult = Wait-Job -Job $job -Timeout $statusUpdateInterval
                $currentTime = Get-Date
                $elapsedTime = ($currentTime - $jobStartTime).TotalSeconds
                
                # Check job state with error handling
                try {
                    $jobState = $job.State
                    Write-ScriptLog -LogFilePath $LogFile -Message "[DEBUG] Job $($job.Id) state: $jobState, HasMoreData: $($job.HasMoreData)"
                } catch {
                    Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] Failed to check job state for $drive : $($_.Exception.Message)"
                    # If we can't check job state, assume it's failed and break
                    break
                }
                
                if (-not $jobResult -and $jobState -eq "Running") {
                    # Job is still running, provide status update
                    if (($currentTime - $lastStatusUpdate).TotalSeconds -ge $statusUpdateInterval) {
                        Write-ScriptLog -LogFilePath $LogFile -Message "[INFO] BitLocker job still running for $drive (Elapsed: $([math]::Round($elapsedTime/60, 1)) minutes)"
                        $lastStatusUpdate = $currentTime
                    }
                } elseif ($jobState -eq "Failed") {
                    Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] BitLocker job failed for $drive"
                    break
                } elseif ($jobState -eq "Completed") {
                    Write-ScriptLog -LogFilePath $LogFile -Message "[INFO] BitLocker job completed for $drive"
                    break
                }
                
                # Check if we've exceeded the total timeout
                if ($elapsedTime -gt $jobTimeout) {
                    Write-ScriptLog -LogFilePath $LogFile -Message "[WARNING] BitLocker job timeout reached for $drive after $([math]::Round($elapsedTime/3600, 1)) hours"
                    break
                }
            } catch {
                Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] Exception in job monitoring loop for $drive : $($_.Exception.Message)"
                Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] Exception details: $($_.Exception.GetType().FullName)"
                Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] Stack trace: $($_.ScriptStackTrace)"
                break
            }
        } while (-not $jobResult -and $job.State -eq "Running")
        
        # Final job result after monitoring loop
        if (-not $jobResult) {
            try {
                $jobResult = Get-Job -Id $job.Id | Where-Object { $_.State -ne "Running" }
                Write-ScriptLog -LogFilePath $LogFile -Message "[DEBUG] Final job result check for $drive : Job State = $($job.State)"
            } catch {
                Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] Failed to get final job result for $drive : $($_.Exception.Message)"
                # Create a dummy failed result to continue processing
                $jobResult = @{ State = "Failed" }
            }
        }
        
        if ($jobResult) {
            # Job completed, get the result
            try {
                # Set non-interactive mode before receiving job output
                $ProgressPreference = 'SilentlyContinue'
                $WarningPreference = 'SilentlyContinue'
                $VerbosePreference = 'SilentlyContinue'
                $DebugPreference = 'SilentlyContinue'
                $InformationPreference = 'SilentlyContinue'
                
                $jobOutput = Receive-Job -Job $job -ErrorAction Stop -WarningAction SilentlyContinue
                Write-ScriptLog -LogFilePath $LogFile -Message "[DEBUG] Received job output for $drive : Success = $($jobOutput.Success)"
                
                try {
                    Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
                    Write-ScriptLog -LogFilePath $LogFile -Message "[DEBUG] Successfully removed job for $drive"
                } catch {
                    Write-ScriptLog -LogFilePath $LogFile -Message "[WARNING] Failed to remove job for $drive : $($_.Exception.Message)"
                }
            } catch {
                $errorMessage = $_.Exception.Message
                Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] Failed to receive job output for $drive : $errorMessage"
                Write-ScriptLog -LogFilePath $LogFile -Message "[DEBUG] Exception type: $($_.Exception.GetType().FullName)"
                Write-ScriptLog -LogFilePath $LogFile -Message "[DEBUG] Exception stack trace: $($_.ScriptStackTrace)"
                
                # Check if this is a UserInteractive error (which may not be a real failure)
                if ($errorMessage -like "*UserInteractive*" -or $errorMessage -like "*显示模式对话框或窗体是无效操作*") {
                    Write-ScriptLog -LogFilePath $LogFile -Message "[WARNING] UserInteractive error detected - attempting alternative BitLocker enablement"
                    Write-ScriptLog -LogFilePath $LogFile -Message "[INFO] Trying WMI-based BitLocker enablement for $drive"
                    
                    # Try WMI-based BitLocker enablement as fallback
                    try {
                        # Use WMI to enable BitLocker in service mode
                        $volume = Get-WmiObject -Namespace "Root\cimv2\Security\MicrosoftVolumeEncryption" -Class "Win32_EncryptableVolume" | Where-Object { $_.DriveLetter -eq $drive }
                        if ($volume) {
                            # First, add recovery password protector
                            $protectorResult = $volume.ProtectKeyWithNumericalPassword()
                            if ($protectorResult.ReturnValue -eq 0) {
                                Write-ScriptLog -LogFilePath $LogFile -Message "[INFO] Recovery password protector added for $drive via WMI"
                                
                                # Enable key protectors
                                $enableResult = $volume.EnableKeyProtectors()
                                if ($enableResult.ReturnValue -eq 0) {
                                    Write-ScriptLog -LogFilePath $LogFile -Message "[INFO] BitLocker key protectors enabled for $drive via WMI"
                                    
                                    # Start encryption
                                    $encryptResult = $volume.Encrypt()
                                    if ($encryptResult.ReturnValue -eq 0) {
                                        Write-ScriptLog -LogFilePath $LogFile -Message "[SUCCESS] BitLocker encryption started for $drive via WMI fallback"
                                        
                                        # Verify the result
                                        Start-Sleep -Seconds 3
                                        $verifyStatus = Get-BitLockerVolume -MountPoint $drive -ErrorAction Stop
                                        
                                        if ($verifyStatus.ProtectionStatus -eq "On" -or $verifyStatus.VolumeStatus -eq "EncryptionInProgress") {
                                            $jobOutput = @{ 
                                                Success = $true
                                                IsUserInteractiveWarning = $true
                                                ErrorMessage = "UserInteractive error resolved via WMI fallback"
                                                MountPoint = $drive
                                                VolumeStatus = $verifyStatus.VolumeStatus
                                                ProtectionStatus = $verifyStatus.ProtectionStatus
                                                EncryptionPercentage = $verifyStatus.EncryptionPercentage
                                            }
                                        } else {
                                            Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] WMI BitLocker enablement verification failed for $drive"
                                            $jobOutput = @{ Success = $false; ErrorMessage = "WMI BitLocker enablement failed verification: Status=$($verifyStatus.VolumeStatus), Protection=$($verifyStatus.ProtectionStatus)" }
                                        }
                                    } else {
                                        Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] WMI BitLocker encryption start failed for $drive (Return: $($encryptResult.ReturnValue))"
                                        $jobOutput = @{ Success = $false; ErrorMessage = "WMI BitLocker encryption start failed (Return: $($encryptResult.ReturnValue))" }
                                    }
                                } else {
                                    Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] WMI BitLocker key protector enablement failed for $drive (Return: $($enableResult.ReturnValue))"
                                    $jobOutput = @{ Success = $false; ErrorMessage = "WMI BitLocker key protector enablement failed (Return: $($enableResult.ReturnValue))" }
                                }
                            } else {
                                Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] WMI BitLocker protector addition failed for $drive (Return: $($protectorResult.ReturnValue))"
                                $jobOutput = @{ Success = $false; ErrorMessage = "WMI BitLocker protector addition failed (Return: $($protectorResult.ReturnValue))" }
                            }
                        } else {
                            Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] Could not find WMI volume for $drive"
                            $jobOutput = @{ Success = $false; ErrorMessage = "WMI volume not found for $drive" }
                        }
                    } catch {
                        Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] WMI BitLocker fallback failed for $drive : $($_.Exception.Message)"
                        $jobOutput = @{ Success = $false; ErrorMessage = "WMI BitLocker fallback failed: $($_.Exception.Message)" }
                    }
                } else {
                    # For other types of errors, create a standard failed output
                    $jobOutput = @{ Success = $false; ErrorMessage = "Failed to receive job output: $errorMessage" }
                }
            }
            
            if ($jobOutput.Success) {
                if ($jobOutput.IsUserInteractiveWarning) {
                    Write-ScriptLog -LogFilePath $LogFile -Message "[WARNING] BitLocker job completed for $drive with UserInteractive warning: $($jobOutput.ErrorMessage)"
                } else {
                    Write-ScriptLog -LogFilePath $LogFile -Message "[SUCCESS] BitLocker job completed successfully for $drive"
                }
                
                # Verify BitLocker status and get recovery key
                try {
                    $currentStatus = Get-BitLockerVolume -MountPoint $drive -ErrorAction Stop
                    
                    if ($currentStatus.VolumeStatus -in @("EncryptionInProgress", "FullyEncrypted")) {
                        # Get recovery key protector (use Select-Object -First 1 to avoid multiple object errors)
                        $protector = $currentStatus | Select-Object -ExpandProperty KeyProtector
                        $recoveryKeyProtector = ($protector | Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" } | Select-Object -First 1)
                        
                        if ($recoveryKeyProtector) {
                            # Export recovery key to file
                            try {
                                $recoveryKeyFile = "$RecoveryKeyPath\$($drive.TrimEnd(':'))-RecoveryKey.txt"
                                $recoveryKeyContent = @"
BitLocker Recovery Key for Drive $drive
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Computer: $env:COMPUTERNAME

Key Protector ID: $($recoveryKeyProtector.KeyProtectorId)
Recovery Password: $($recoveryKeyProtector.RecoveryPassword)

Instructions:
1. Use this recovery password if you cannot unlock the drive normally
2. Keep this information in a secure location
3. The recovery password is case-sensitive
"@
                                $recoveryKeyContent | Out-File -FilePath $recoveryKeyFile -Encoding UTF8 -Force
                                Write-ScriptLog -LogFilePath $LogFile -Message "[SUCCESS] Recovery key exported to: $recoveryKeyFile"
                            } catch {
                                Write-ScriptLog -LogFilePath $LogFile -Message "[WARNING] Failed to export recovery key to file: $($_.Exception.Message)"
                            }
                            
                            $results += [PSCustomObject]@{
                                Drive            = $drive
                                RecoveryKeyId    = $recoveryKeyProtector.KeyProtectorId
                                RecoveryPassword = $recoveryKeyProtector.RecoveryPassword
                                Status           = "Success"
                                IsSystemDrive    = ($drive -eq "C:")
                                SubmittedToForms = $false
                            }
                            
                            # Handle system drive (C:) and data drives differently
                            if ($drive -eq "C:") {
                                # System drive: No monitoring or AutoUnlock needed
                                Write-ScriptLog -LogFilePath $LogFile -Message "[INFO] System drive $drive - BitLocker enabled successfully, no additional monitoring required"
                                Write-ScriptLog -LogFilePath $LogFile -Message "[INFO] System drive will auto-unlock during boot, AutoUnlock feature not applicable"

                                # Verify TPM-based protector presence; add if missing to prevent recovery prompts
                                Write-ScriptLog -LogFilePath $LogFile -Message "[CHECK] Verifying TPM protector for system drive $drive"
                                $tpmEnsured = Enable-OsDriveTpmProtector -MountPoint $drive -LogFile $LogFile
                                if ($tpmEnsured) {
                                    Write-ScriptLog -LogFilePath $LogFile -Message "[INFO] TPM protector verified/added for system drive $drive"
                                } else {
                                    Write-ScriptLog -LogFilePath $LogFile -Message "[WARNING] TPM protector missing or could not be added on $drive. System may prompt for recovery on reboot."
                                }
                            } elseif ($currentStatus.VolumeStatus -eq "EncryptionInProgress") {
                                # Data drives: Add to monitoring list for parallel processing
                                Write-ScriptLog -LogFilePath $LogFile -Message "[INFO] Adding data drive $drive to parallel monitoring queue"
                                $drivesToMonitor += $drive
                            } elseif ($currentStatus.VolumeStatus -eq "FullyEncrypted") {
                                # Data drives that are already fully encrypted: Enable AutoUnlock immediately
                                Write-ScriptLog -LogFilePath $LogFile -Message "[INFO] Data drive $drive already fully encrypted, enabling Auto-Unlock"
                                $enabled = Enable-DataDriveAutoUnlock -MountPoint $drive
                                if ($enabled) {
                                    Write-ScriptLog -LogFilePath $LogFile -Message "[SUCCESS] Auto-Unlock enabled for $drive"
                                } else {
                                    Write-ScriptLog -LogFilePath $LogFile -Message "[WARNING] Auto-Unlock enable failed for $drive"
                                }
                            }
                            
                        } else {
                            Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] No recovery password protector found for $drive"
                            $results += [PSCustomObject]@{
                                Drive = $drive
                                Status = "PartialSuccess"
                                RecoveryKeyId = "N/A"
                                RecoveryPassword = "N/A"
                                ErrorMessage = "Recovery password protector not found"
                                IsSystemDrive = ($drive -eq "C:")
                            }
                        }
                    } else {
                        Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] BitLocker not in expected state for $drive (Status: $($currentStatus.VolumeStatus))"
                        $results += [PSCustomObject]@{
                            Drive = $drive
                            Status = "Failed"
                            RecoveryKeyId = $null
                            RecoveryPassword = $null
                            ErrorMessage = "BitLocker not in expected state: $($currentStatus.VolumeStatus)"
                            IsSystemDrive = ($drive -eq "C:")
                        }
                    }
                } catch {
                    Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] Failed to verify BitLocker status for $drive : $($_.Exception.Message)"
                    $results += [PSCustomObject]@{
                        Drive = $drive
                        Status = "PartialSuccess"
                        RecoveryKeyId = "N/A"
                        RecoveryPassword = "N/A"
                        ErrorMessage = "Failed to verify BitLocker status: $($_.Exception.Message)"
                        IsSystemDrive = ($drive -eq "C:")
                    }
                }
            } else {
                try {
                    Write-ScriptLog -LogFilePath $LogFile -Message "[DEBUG] Processing failed job for drive $drive"
                    Write-ScriptLog -LogFilePath $LogFile -Message "[DEBUG] Job output type: $($jobOutput.GetType().FullName)"
                    Write-ScriptLog -LogFilePath $LogFile -Message "[DEBUG] Job output content: $($jobOutput | ConvertTo-Json -Depth 2 -ErrorAction SilentlyContinue)"
                    
                    $errorMessage = if ($jobOutput -and $jobOutput.ErrorMessage) {
                        $jobOutput.ErrorMessage
                    } elseif ($jobOutput -and $jobOutput.ToString()) {
                        $jobOutput.ToString()
                    } else {
                        "Unknown job failure - no error details available"
                    }
                    
                    Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] BitLocker job failed for $drive : $errorMessage"
                    
                    # Check for TPM compatibility error
                    if ($errorMessage -like "*$($SCRIPT_CONSTANTS.TPM_COMPATIBILITY_ERROR_CODE)*" -or 
                        $errorMessage -like "*兼容的受信任的平台模块*" -or 
                        $errorMessage -like "*compatible Trusted Platform Module*") {
                        
                        Write-ScriptLog -LogFilePath $LogFile -Message "[CRITICAL ERROR] $($SCRIPT_CONSTANTS.ERROR_MESSAGES.TPM_NOT_COMPATIBLE) detected on $drive"
                        Write-ScriptLog -LogFilePath $LogFile -Message "[EXITING] Stopping BitLocker enablement process due to TPM incompatibility"
                        
                        $results += [PSCustomObject]@{
                            Drive            = $drive
                            RecoveryKeyId    = $null
                            RecoveryPassword = $null
                            Status           = "Critical_TPM_Error"
                            ErrorMessage     = "$($SCRIPT_CONSTANTS.ERROR_MESSAGES.TPM_NOT_COMPATIBLE) - $errorMessage"
                            IsSystemDrive    = ($drive -eq "C:")
                        }
                        
                        # Cancel remaining jobs and return
                        foreach ($remainingJobInfo in $bitlockerJobs) {
                            if ($remainingJobInfo.Job.State -eq "Running") {
                                Stop-Job -Job $remainingJobInfo.Job
                                Remove-Job -Job $remainingJobInfo.Job
                            }
                        }
                        
                        Write-ScriptLog -LogFilePath $LogFile -Message "=== BitLocker Enablement Process TERMINATED due to TPM issues ==="
                        return $results
                    }
                    
                    $results += [PSCustomObject]@{
                        Drive            = $drive
                        RecoveryKeyId    = $null
                        RecoveryPassword = $null
                        Status           = "Failed"
                        ErrorMessage     = $errorMessage
                        IsSystemDrive    = ($drive -eq "C:")
                    }
                } catch {
                    Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] Exception in job failure processing for $drive : $($_.Exception.Message)"
                    Write-ScriptLog -LogFilePath $LogFile -Message "[DEBUG] Exception stack trace: $($_.ScriptStackTrace)"
                    
                    $results += [PSCustomObject]@{
                        Drive            = $drive
                        RecoveryKeyId    = $null
                        RecoveryPassword = $null
                        Status           = "Failed"
                        ErrorMessage     = "Job failure processing error: $($_.Exception.Message)"
                        IsSystemDrive    = ($drive -eq "C:")
                    }
                }
            }
        } else {
            # Job timed out or failed to complete
            Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] BitLocker enablement job timed out for $drive (Job ID: $($job.Id)) after $([math]::Round($jobTimeout/3600, 1)) hours"
            Write-ScriptLog -LogFilePath $LogFile -Message "[INFO] This timeout is for BitLocker enablement job completion, not encryption completion"
            Write-ScriptLog -LogFilePath $LogFile -Message "[INFO] BitLocker may still be running in the background - checking current status..."
            
            # Check if BitLocker was actually enabled despite job timeout
            try {
                $currentStatus = Get-BitLockerVolume -MountPoint $drive -ErrorAction SilentlyContinue
                if ($currentStatus -and ($currentStatus.VolumeStatus -in @("EncryptionInProgress", "FullyEncrypted"))) {
                    Write-ScriptLog -LogFilePath $LogFile -Message "[INFO] BitLocker appears to be active on $drive despite job timeout (Status: $($currentStatus.VolumeStatus))"
                    Write-ScriptLog -LogFilePath $LogFile -Message "[INFO] Continuing with monitoring and recovery key export..."
                    
                    # Try to get recovery key even though job timed out
                    $protector = $currentStatus | Select-Object -ExpandProperty KeyProtector
                    $recoveryKeyProtector = ($protector | Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" } | Select-Object -First 1)
                    
                    if ($recoveryKeyProtector) {
                        try {
                            $recoveryKeyFile = "$RecoveryKeyPath\$($drive.TrimEnd(':'))-RecoveryKey.txt"
                            $recoveryKeyContent = @"
BitLocker Recovery Key for Drive $drive
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Computer: $env:COMPUTERNAME

Key Protector ID: $($recoveryKeyProtector.KeyProtectorId)
Recovery Password: $($recoveryKeyProtector.RecoveryPassword)

Instructions:
1. Use this recovery password if you cannot unlock the drive normally
2. Keep this information in a secure location
3. The recovery password is case-sensitive
"@
                            $recoveryKeyContent | Out-File -FilePath $recoveryKeyFile -Encoding UTF8 -Force
                            Write-ScriptLog -LogFilePath $LogFile -Message "[SUCCESS] Recovery key exported despite job timeout: $recoveryKeyFile"
                            
                            $results += [PSCustomObject]@{
                                Drive            = $drive
                                RecoveryKeyId    = $recoveryKeyProtector.KeyProtectorId
                                RecoveryPassword = $recoveryKeyProtector.RecoveryPassword
                                Status           = "PartialSuccess"
                                ErrorMessage     = "Job timed out but BitLocker is active"
                                IsSystemDrive    = ($drive -eq "C:")
                            }
                        } catch {
                            Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] Failed to export recovery key despite active BitLocker: $($_.Exception.Message)"
                            $results += [PSCustomObject]@{
                                Drive            = $drive
                                RecoveryKeyId    = $null
                                RecoveryPassword = $null
                                Status           = "PartialSuccess"
                                ErrorMessage     = "Job timed out, BitLocker active but recovery key export failed"
                                IsSystemDrive    = ($drive -eq "C:")
                            }
                        }
                    } else {
                        $results += [PSCustomObject]@{
                            Drive            = $drive
                            RecoveryKeyId    = $null
                            RecoveryPassword = $null
                            Status           = "PartialSuccess"
                            ErrorMessage     = "Job timed out, BitLocker active but no recovery key found"
                            IsSystemDrive    = ($drive -eq "C:")
                        }
                    }
                } else {
                    Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] BitLocker job timed out and BitLocker is not active on $drive"
                    $results += [PSCustomObject]@{
                        Drive            = $drive
                        RecoveryKeyId    = $null
                        RecoveryPassword = $null
                        Status           = "Failed"
                        ErrorMessage     = "BitLocker enablement job timed out after $([math]::Round($jobTimeout/3600, 1)) hours and BitLocker is not active"
                        IsSystemDrive    = ($drive -eq "C:")
                    }
                }
            } catch {
                Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] Failed to check BitLocker status after job timeout: $($_.Exception.Message)"
                $results += [PSCustomObject]@{
                    Drive            = $drive
                    RecoveryKeyId    = $null
                    RecoveryPassword = $null
                    Status           = "Failed"
                    ErrorMessage     = "Job timed out and status check failed: $($_.Exception.Message)"
                    IsSystemDrive    = ($drive -eq "C:")
                }
            }
            
            # Clean up the timed out job
            try {
                Stop-Job -Job $job -ErrorAction SilentlyContinue
                Remove-Job -Job $job -ErrorAction SilentlyContinue
            } catch {
                Write-ScriptLog -LogFilePath $LogFile -Message "[WARNING] Failed to clean up timed out job: $($_.Exception.Message)"
            }
        }
    }

    Write-ScriptLog -LogFilePath $LogFile -Message "[STEP Final] Verifying Auto-Unlock on all non-system drives..."
    foreach ($drv in $validDrives | Where-Object { $_ -ne "C:" }) {
        $normalized = $drv.TrimEnd(":") + ":"
        $status = Get-BitLockerVolume -MountPoint $normalized -ErrorAction SilentlyContinue
        if ($status -and $status.VolumeStatus -eq "FullyEncrypted" -and -not $status.AutoUnlockEnabled) {
            Write-ScriptLog -LogFilePath $LogFile -Message "[INFO] Attempting Auto-unlock compensation for $normalized"
            $enabled = Enable-DataDriveAutoUnlock -MountPoint $normalized
            if ($enabled) {
                Write-ScriptLog -LogFilePath $LogFile -Message "[SUCCESS] Auto-unlock compensation successful: $normalized"
            } else {
                Write-ScriptLog -LogFilePath $LogFile -Message "[WARNING] Auto-unlock compensation failed: $normalized"
            }
        } elseif ($status -and $status.VolumeStatus -eq "FullyEncrypted" -and $status.AutoUnlockEnabled) {
            Write-ScriptLog -LogFilePath $LogFile -Message "[INFO] Auto-unlock already enabled for $normalized"
        } elseif ($status -and $status.VolumeStatus -eq "Unknown") {
            # Layered handling for Unknown but accessible volumes
            Write-ScriptLog -LogFilePath $LogFile -Message "[NOTICE] $normalized status Unknown during final check — attempting refresh and reset"
            $refresh = Get-ManageBdeStatusInfo -MountPoint $normalized -LogFile $LogFile
            if ($refresh) {
                Write-ScriptLog -LogFilePath $LogFile -Message "[SUCCESS] ManageBdeStatusInfo refresh successful for $normalized"
            } else {
                Write-ScriptLog -LogFilePath $LogFile -Message "[WARNING] ManageBdeStatusInfo refresh failed for $normalized"
            }

            $pathAccessible = $false
            try { $pathAccessible = Test-Path "$normalized\" -ErrorAction SilentlyContinue } catch { $pathAccessible = $false }
            if ($pathAccessible) {
                [void](Reset-DataDriveAutoUnlock -MountPoint $normalized -LogFile $LogFile)
            } else {
                Write-ScriptLog -LogFilePath $LogFile -Message "[NOTICE] $normalized not accessible; skipping reset"
            }
        } elseif ($status -and $status.VolumeStatus -ne "FullyEncrypted") {
            Write-ScriptLog -LogFilePath $LogFile -Message "[INFO] Drive $normalized not fully encrypted (Status: $($status.VolumeStatus)), skipping Auto-unlock compensation"
        }
    }

    $successfulDrives = $results | Where-Object { $_.Status -eq "Success" }
    $partialSuccessDrives = $results | Where-Object { $_.Status -eq "PartialSuccess" }
    $failedDrives = $results | Where-Object { $_.Status -eq "Failed" -or $_.Status -eq "Critical_TPM_Error" }
    
    Write-ScriptLog -LogFilePath $LogFile -Message "=== BitLocker Enablement Process Summary ==="
    Write-ScriptLog -LogFilePath $LogFile -Message "Total drives processed: $($results.Count)"
    Write-ScriptLog -LogFilePath $LogFile -Message "Successful: $($successfulDrives.Count)"
    Write-ScriptLog -LogFilePath $LogFile -Message "Partial Success: $($partialSuccessDrives.Count)"
    Write-ScriptLog -LogFilePath $LogFile -Message "Failed: $($failedDrives.Count)"
    
    if ($successfulDrives.Count -gt 0) {
        Write-ScriptLog -LogFilePath $LogFile -Message "Successfully encrypted drives: $($successfulDrives.Drive -join ', ')"
    }
    
    if ($partialSuccessDrives.Count -gt 0) {
        Write-ScriptLog -LogFilePath $LogFile -Message "Partially successful drives: $($partialSuccessDrives.Drive -join ', ')"
    }
    
    if ($failedDrives.Count -gt 0) {
        Write-ScriptLog -LogFilePath $LogFile -Message "Failed drives: $($failedDrives.Drive -join ', ')"
    }
    
    if ($results.Count -eq 0 -or $successfulDrives.Count -eq 0) {
        Write-ScriptLog -LogFilePath $LogFile -Message "[WARNING] No drives were successfully encrypted"
    }
    
    Write-ScriptLog -LogFilePath $LogFile -Message "=== BitLocker Enablement Process Complete ==="
    
    # Start parallel monitoring for drives that need it
    if ($drivesToMonitor.Count -gt 0) {
        # Detect non-interactive/EXE environment and skip background monitoring jobs to avoid Start-Job hang
        $isNonInteractive = $false
        try {
            $isNonInteractive = -not [Environment]::UserInteractive -or 
                               (Get-Process -Id $PID).SessionId -eq 0 -or
                               [string]::IsNullOrEmpty($env:USERNAME)
        } catch {
            # If environment detection fails, assume non-interactive for safety
            $isNonInteractive = $true
        }

        if ($isNonInteractive) {
            Write-ScriptLog -LogFilePath $LogFile -Message "[MONITOR SKIP] Non-interactive/EXE mode detected - skipping background monitoring jobs"
            Write-ScriptLog -LogFilePath $LogFile -Message "Drives to monitor (skipped): $($drivesToMonitor -join ', ')"
            Write-ScriptLog -LogFilePath $LogFile -Message "[INFO] Encryption continues in background. Validate via Get-BitLockerVolume or Event Logs."
        } else {
            Write-ScriptLog -LogFilePath $LogFile -Message "=== Starting Parallel Monitoring for $($drivesToMonitor.Count) drives ==="
            Write-ScriptLog -LogFilePath $LogFile -Message "Drives to monitor: $($drivesToMonitor -join ', ')"
            
            # Create monitoring jobs for each drive
            $monitoringJobs = @()
            foreach ($driveToMonitor in $drivesToMonitor) {
                Write-ScriptLog -LogFilePath $LogFile -Message "[MONITOR START] Creating monitoring job for drive $driveToMonitor"
                
                $monitoringJob = Start-Job -ScriptBlock {
                    param($Drive, $LogFile, $ScriptRoot)
                    
                    # Import the Watch-BitLockerStatus function
                    $scriptPath = Join-Path $ScriptRoot "EnableBitLocker.ps1"
                    if (Test-Path $scriptPath) {
                        . $scriptPath
                    } else {
                        # Fallback paths
                        $fallbackPaths = @(
                            "D:\Powershell\EnableBitLocker\EnableBitLocker.ps1",
                            ".\EnableBitLocker.ps1",
                            (Join-Path (Get-Location) "EnableBitLocker.ps1")
                        )
                        
                        $loaded = $false
                        foreach ($path in $fallbackPaths) {
                            if (Test-Path $path) {
                                . $path
                                $loaded = $true
                                break
                            }
                        }
                        
                        if (-not $loaded) {
                            throw "Could not find EnableBitLocker.ps1 script to load Watch-BitLockerStatus function"
                        }
                    }
                    
                    # Call the monitoring function
                    try {
                        $result = Watch-BitLockerStatus -MountPoint $Drive -IntervalSeconds 30 -TimeoutSeconds 7200 -LogFile $LogFile
                        return @{
                            Drive = $Drive
                            Success = $result
                            Error = $null
                        }
                    } catch {
                        return @{
                            Drive = $Drive
                            Success = $false
                            Error = $_.Exception.Message
                        }
                    }
                } -ArgumentList $driveToMonitor, $LogFile, $PSScriptRoot
                
                $monitoringJobs += [PSCustomObject]@{
                    Drive = $driveToMonitor
                    Job = $monitoringJob
                }
            }
            
            Write-ScriptLog -LogFilePath $LogFile -Message "[MONITOR INFO] Started $($monitoringJobs.Count) parallel monitoring jobs"
            Write-ScriptLog -LogFilePath $LogFile -Message "[MONITOR INFO] Monitoring jobs will run in background and complete automatically"
            Write-ScriptLog -LogFilePath $LogFile -Message "[MONITOR INFO] Check the log file for monitoring progress updates"
            
            # Optional: Wait for a short time to ensure jobs are started properly
            Start-Sleep -Seconds 5
            
            # Check job status
            foreach ($monJob in $monitoringJobs) {
                $jobState = $monJob.Job.State
                Write-ScriptLog -LogFilePath $LogFile -Message "[MONITOR STATUS] Drive $($monJob.Drive) monitoring job state: $jobState"
            }
        }
    }
    
    return $results
}


function Submit-MicrosoftForm {
    param(
        [Parameter(Mandatory)]
        [string]$TenantId,   
        [Parameter(Mandatory)]
        [string]$UserId,     
        [Parameter(Mandatory)]
        [string]$FormInternalId, 
        [Parameter(Mandatory)]
        [array]$Answers,
        [Parameter(Mandatory)]
        [string]$LogFile,
        [Parameter(Mandatory = $false)]
        [string]$AnonymousToken
    )

    Write-ScriptLog -LogFilePath $LogFile -Message "=== Starting Microsoft Forms API Submission Process ==="
    Write-ScriptLog -LogFilePath $LogFile -Message "Tenant ID: $TenantId"
    Write-ScriptLog -LogFilePath $LogFile -Message "User ID: $UserId"
    Write-ScriptLog -LogFilePath $LogFile -Message "Form Internal ID: $FormInternalId"
    Write-ScriptLog -LogFilePath $LogFile -Message "Number of answers to submit: $($Answers.Count)"

    # Build target API URL
    $url = "https://forms.office.com/formapi/api/$TenantId/users/$UserId/forms('$FormInternalId')/responses"
    Write-ScriptLog -LogFilePath $LogFile -Message "Target API URL: $url"
    
    # Convert answers to API format
    Write-ScriptLog -LogFilePath $LogFile -Message "[STEP 1] Converting answers to Microsoft Forms API format..."
    $answerIndex = 0
    foreach ($answer in $Answers) {
        $answerIndex++
        # Log answer details (mask sensitive recovery passwords)
        if ($answer.answer1 -match "^\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}$") {
            Write-ScriptLog -LogFilePath $LogFile -Message "Answer $answerIndex - Question ID: $($answer.questionId), Value: [RECOVERY PASSWORD - MASKED]"
        } else {
            $answerPreview = if ($answer.answer1.Length -gt 50) { $answer.answer1.Substring(0, 47) + "..." } else { $answer.answer1 }
            Write-ScriptLog -LogFilePath $LogFile -Message "Answer $answerIndex - Question ID: $($answer.questionId), Value: $answerPreview"
        }
    }
    
    # === STEP 1: Normalize answers ===
    Write-ScriptLog -LogFilePath $LogFile -Message "[STEP 1] Normalizing answers for Microsoft Forms API..."
    $normalizedAnswers = @()
    foreach ($answer in $Answers) {
        $normalizedAnswers += @{ 
            questionId = $answer.questionId 
            answer     = @($answer.answer1)  # Always an array, even for single answers 
        }
    }

    # === STEP 2: Build request body ===
    $requestBody = @{ 
        answers                = $normalizedAnswers 
        anonymousResponseToken = $AnonymousToken 
    } | ConvertTo-Json -Depth 5 -Compress

    $bodyPreview = if ($requestBody.Length -gt 400) { $requestBody.Substring(0, 397) + "..." } else { $requestBody }
    Write-ScriptLog -LogFilePath $LogFile -Message "Request body prepared (length: $($requestBody.Length) characters)"
    Write-ScriptLog -LogFilePath $LogFile -Message "Request body preview: $bodyPreview"

    try {
        Write-ScriptLog -LogFilePath $LogFile -Message "[STEP 2] Submitting data to Microsoft Forms API..."
        Write-ScriptLog -LogFilePath $LogFile -Message "HTTP Method: POST"
        Write-ScriptLog -LogFilePath $LogFile -Message "Content-Type: application/json"
        Write-ScriptLog -LogFilePath $LogFile -Message "Timeout: 30 seconds"
        
        $response = Invoke-RestMethod -Uri $url -Method Post `
            -Body $requestBody `
            -ContentType "application/json" `
            -TimeoutSec 30
        
        Write-ScriptLog -LogFilePath $LogFile -Message "[SUCCESS] API call completed successfully"
        
        # Check if response contains expected data structure
        if ($response -and $response.PSObject.Properties['id']) {
            Write-ScriptLog -LogFilePath $LogFile -Message "[SUCCESS] Form response created with ID: $($response.id)"
            Write-ScriptLog -LogFilePath $LogFile -Message "Response Start Date: $($response.startDate)"
            Write-ScriptLog -LogFilePath $LogFile -Message "Response Submit Date: $($response.submitDate)"
            Write-ScriptLog -LogFilePath $LogFile -Message "Responder: $($response.responder)"
            Write-ScriptLog -LogFilePath $LogFile -Message "[SUCCESS] BitLocker recovery information successfully submitted to Microsoft Forms"
        } else {
            Write-ScriptLog -LogFilePath $LogFile -Message "[WARNING] API call returned unexpected response format"
            Write-ScriptLog -LogFilePath $LogFile -Message "Response: $($response | ConvertTo-Json -Compress)"
        }
        
        Write-ScriptLog -LogFilePath $LogFile -Message "=== Microsoft Forms API Submission Process Complete ==="
        return $response
        
    } catch {
        Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] Exception occurred during API submission process"
        Write-ScriptLog -LogFilePath $LogFile -Message "Error Type: $($_.Exception.GetType().FullName)"
        Write-ScriptLog -LogFilePath $LogFile -Message "Error Message: $($_.Exception.Message)"
        
        # Handle HTTP-specific errors
        if ($_.Exception -is [System.Net.WebException]) {
            $webException = $_.Exception
            if ($webException.Response) {
                $statusCode = [int]$webException.Response.StatusCode
                $statusDescription = $webException.Response.StatusDescription
                Write-ScriptLog -LogFilePath $LogFile -Message "HTTP Status Code: $statusCode $statusDescription"
                
                # Try to read error response content
                try {
                    $errorStream = $webException.Response.GetResponseStream()
                    $reader = New-Object System.IO.StreamReader($errorStream)
                    $errorContent = $reader.ReadToEnd()
                    $reader.Close()
                    $errorStream.Close()
                    
                    if (-not [string]::IsNullOrEmpty($errorContent)) {
                        Write-ScriptLog -LogFilePath $LogFile -Message "Error Response Content: $errorContent"
                    }
                } catch {
                    Write-ScriptLog -LogFilePath $LogFile -Message "Unable to read error response content: $($_.Exception.Message)"
                }
            }
        }
        
        if ($_.Exception.InnerException) {
            Write-ScriptLog -LogFilePath $LogFile -Message "Inner Exception: $($_.Exception.InnerException.Message)"
        }
        
        Write-ScriptLog -LogFilePath $LogFile -Message "=== Microsoft Forms API Submission Process Failed ==="
        return $null
    }
}


function Set-SecureBootRegistryConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$LogFile
    )
    
    Write-ScriptLog -LogFilePath $LogFile -Message "=== Starting Registry Configuration ==="
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"
    $regName = "AvailableUpdates"
    $expectedValue = 0x40

    Write-ScriptLog -LogFilePath $LogFile -Message "[STEP 1] Configuring SecureBoot registry settings"
    Write-ScriptLog -LogFilePath $LogFile -Message "Registry Path: $regPath"
    Write-ScriptLog -LogFilePath $LogFile -Message "Registry Key: $regName"
    Write-ScriptLog -LogFilePath $LogFile -Message "Expected Value: 0x$($expectedValue.ToString('X'))"

    try {
        Write-ScriptLog -LogFilePath $LogFile -Message "[INFO] Attempting to read current registry value..."
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).$regName
        Write-ScriptLog -LogFilePath $LogFile -Message "[SUCCESS] Current registry value retrieved: 0x$($currentValue.ToString('X'))"

        if ($currentValue -eq $expectedValue) {
            Write-ScriptLog -LogFilePath $LogFile -Message "[SUCCESS] Registry value is already correct (0x$($expectedValue.ToString('X')))"
            Write-ScriptLog -LogFilePath $LogFile -Message "[INFO] No registry modification required"
            return $true
        }
        else {
            Write-ScriptLog -LogFilePath $LogFile -Message "[WARNING] Registry value mismatch detected"
            Write-ScriptLog -LogFilePath $LogFile -Message "Current: 0x$($currentValue.ToString('X')), Expected: 0x$($expectedValue.ToString('X'))"
            Write-ScriptLog -LogFilePath $LogFile -Message "[ACTION] Updating registry value..."
            
            Set-ItemProperty -Path $regPath -Name $regName -Value $expectedValue -ErrorAction Stop
            
            # Verify the change
            $verifyValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).$regName
            if ($verifyValue -eq $expectedValue) {
                Write-ScriptLog -LogFilePath $LogFile -Message "[SUCCESS] Registry value updated successfully to 0x$($expectedValue.ToString('X'))"
                return $true
            } else {
                Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] Registry value verification failed. Expected: 0x$($expectedValue.ToString('X')), Actual: 0x$($verifyValue.ToString('X'))"
                return $false
            }
        }
    }
    catch {
        Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] Failed to read registry key '$regName'"
        Write-ScriptLog -LogFilePath $LogFile -Message "Error Type: $($_.Exception.GetType().FullName)"
        Write-ScriptLog -LogFilePath $LogFile -Message "Error Message: $($_.Exception.Message)"
        
        Write-ScriptLog -LogFilePath $LogFile -Message "[RECOVERY] Attempting to create/set registry value..."
        try {
            # Check if registry path exists
            if (-not (Test-Path $regPath)) {
                Write-ScriptLog -LogFilePath $LogFile -Message "[INFO] Registry path does not exist, creating: $regPath"
                New-Item -Path $regPath -Force -ErrorAction Stop | Out-Null
            }
            
            Set-ItemProperty -Path $regPath -Name $regName -Value $expectedValue -ErrorAction Stop
            
            # Verify the creation/update
            $verifyValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).$regName
            if ($verifyValue -eq $expectedValue) {
                Write-ScriptLog -LogFilePath $LogFile -Message "[SUCCESS] Registry value created/updated successfully to 0x$($expectedValue.ToString('X'))"
                return $true
            } else {
                Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] Registry value verification failed after creation. Expected: 0x$($expectedValue.ToString('X')), Actual: 0x$($verifyValue.ToString('X'))"
                return $false
            }
        }
        catch {
            Write-ScriptLog -LogFilePath $LogFile -Message "[CRITICAL] Failed to create/set registry value '$regName'"
            Write-ScriptLog -LogFilePath $LogFile -Message "Error Type: $($_.Exception.GetType().FullName)"
            Write-ScriptLog -LogFilePath $LogFile -Message "Error Message: $($_.Exception.Message)"
            Write-ScriptLog -LogFilePath $LogFile -Message "[WARNING] Registry configuration failed, but continuing script execution"
            return $false
        }
    }
    finally {
        Write-ScriptLog -LogFilePath $LogFile -Message "=== Registry Configuration Complete ==="
    }
}


function Start-SecureBootUpdateTask {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$LogFile,
        
        [Parameter(Mandatory = $false)]
        [string]$TaskName = "\Microsoft\Windows\PI\Secure-Boot-Update"
    )
    
    Write-ScriptLog -LogFilePath $LogFile -Message "=== Starting Scheduled Task Execution ==="
    
    Write-ScriptLog -LogFilePath $LogFile -Message "[STEP 1] Preparing to execute scheduled task"
    Write-ScriptLog -LogFilePath $LogFile -Message "Task Name: $TaskName"
    
    try {
        # Check if task exists using schtasks command first
        Write-ScriptLog -LogFilePath $LogFile -Message "[INFO] Verifying scheduled task existence using schtasks..."
        & schtasks /query /tn $TaskName 2>$null | Out-Null
        
        if ($LASTEXITCODE -ne 0) {
            Write-ScriptLog -LogFilePath $LogFile -Message "[WARNING] Scheduled task '$TaskName' not found using schtasks command"
            Write-ScriptLog -LogFilePath $LogFile -Message "[INFO] Attempting PowerShell Get-ScheduledTask as fallback..."
        }
        
        # Try PowerShell method as fallback
        $task = Get-ScheduledTask | Where-Object { $_.TaskPath + $_.TaskName -eq $TaskName } | Select-Object -First 1
        
        if (-not $task) {
            # Try alternative task name formats
            $alternativeTaskName = $TaskName -replace '^\\Microsoft\\Windows\\PI\\', ''
            $task = Get-ScheduledTask | Where-Object { $_.TaskName -eq $alternativeTaskName -and $_.TaskPath -like '*PI*' } | Select-Object -First 1
        }
        
        if (-not $task) {
            Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] Scheduled task not found: $TaskName"
            Write-ScriptLog -LogFilePath $LogFile -Message "[INFO] Task may not exist on this system or may require different permissions"
            
            # List available PI-related tasks for debugging
            try {
                $piTasks = Get-ScheduledTask | Where-Object { $_.TaskPath -like '*PI*' }
                if ($piTasks) {
                    Write-ScriptLog -LogFilePath $LogFile -Message "[INFO] Found PI-related scheduled tasks:"
                    foreach ($piTask in $piTasks) {
                        Write-ScriptLog -LogFilePath $LogFile -Message "  - $($piTask.TaskPath)$($piTask.TaskName) (State: $($piTask.State))"
                    }
                } else {
                    Write-ScriptLog -LogFilePath $LogFile -Message "[INFO] No PI-related scheduled tasks found"
                }
            } catch {
                Write-ScriptLog -LogFilePath $LogFile -Message "[WARNING] Could not enumerate PI-related tasks for debugging"
            }
            
            Write-ScriptLog -LogFilePath $LogFile -Message "[INFO] SecureBoot update will be handled by registry configuration only"
            Write-ScriptLog -LogFilePath $LogFile -Message "[INFO] System will apply SecureBoot updates on next reboot"
            return $true  # Return true as registry configuration is sufficient
        }
        
        # Task found, proceed with execution
        Write-ScriptLog -LogFilePath $LogFile -Message "[SUCCESS] Scheduled task found"
        $task = Get-ScheduledTask -TaskName ($task.TaskName) -TaskPath ($task.TaskPath) -ErrorAction Stop
        
        if ($task) {
            Write-ScriptLog -LogFilePath $LogFile -Message "[SUCCESS] Scheduled task found"
            Write-ScriptLog -LogFilePath $LogFile -Message "Task State: $($task.State)"
            Write-ScriptLog -LogFilePath $LogFile -Message "Task Path: $($task.TaskPath)"
            Write-ScriptLog -LogFilePath $LogFile -Message "Last Run Time: $($task.LastRunTime)"
            Write-ScriptLog -LogFilePath $LogFile -Message "Next Run Time: $($task.NextRunTime)"
            
            # Check current task state
            if ($task.State -eq "Running") {
                Write-ScriptLog -LogFilePath $LogFile -Message "[WARNING] Task is already running"
                return $true  # Task is already running, consider it successful
            } elseif ($task.State -eq "Disabled") {
                Write-ScriptLog -LogFilePath $LogFile -Message "[WARNING] Task is currently disabled"
            }
            
            Write-ScriptLog -LogFilePath $LogFile -Message "[STEP 2] Starting scheduled task execution..."
            Start-ScheduledTask -TaskName $TaskName -ErrorAction Stop
            
            # Brief wait to check if task started successfully
            Start-Sleep -Seconds 2
            $taskAfterStart = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
            
            if ($taskAfterStart -and $taskAfterStart.State -eq "Running") {
                Write-ScriptLog -LogFilePath $LogFile -Message "[SUCCESS] Scheduled task started successfully and is now running"
                
                Write-ScriptLog -LogFilePath $LogFile -Message "[INFO] Applying random delay before script completion..."
                #Start-RandomSleep -Min 1 -Max 10
                
                Write-ScriptLog -LogFilePath $LogFile -Message "[SUCCESS] Scheduled task execution initiated successfully"
                return $true
            } else {
                Write-ScriptLog -LogFilePath $LogFile -Message "[WARNING] Task start command completed, but task state is: $($taskAfterStart.State)"
                return $false
            }
        }
    }
    catch [Microsoft.PowerShell.Cmdletization.Cim.CimJobException] {
        Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] Scheduled task not found or access denied"
        Write-ScriptLog -LogFilePath $LogFile -Message "Task Name: $TaskName"
        Write-ScriptLog -LogFilePath $LogFile -Message "Error Type: Task Not Found or Permission Denied"
        Write-ScriptLog -LogFilePath $LogFile -Message "Error Message: $($_.Exception.Message)"
        
        # Try to list available tasks for debugging
        try {
            $availableTasks = Get-ScheduledTask | Where-Object { $_.TaskName -like "*Secure-Boot*" -or $_.TaskName -like "*PI*" }
            if ($availableTasks) {
                Write-ScriptLog -LogFilePath $LogFile -Message "[INFO] Found related scheduled tasks:"
                foreach ($relatedTask in $availableTasks) {
                    Write-ScriptLog -LogFilePath $LogFile -Message "  - $($relatedTask.TaskPath)$($relatedTask.TaskName) (State: $($relatedTask.State))"
                }
            } else {
                Write-ScriptLog -LogFilePath $LogFile -Message "[INFO] No related scheduled tasks found"
            }
        } catch {
            Write-ScriptLog -LogFilePath $LogFile -Message "[WARNING] Could not enumerate scheduled tasks for debugging"
        }
        
        return $false
    }
    catch {
        Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] Exception occurred during scheduled task execution"
        Write-ScriptLog -LogFilePath $LogFile -Message "Task Name: $TaskName"
        Write-ScriptLog -LogFilePath $LogFile -Message "Error Type: $($_.Exception.GetType().FullName)"
        Write-ScriptLog -LogFilePath $LogFile -Message "Error Message: $($_.Exception.Message)"
        
        if ($_.Exception.InnerException) {
            Write-ScriptLog -LogFilePath $LogFile -Message "Inner Exception: $($_.Exception.InnerException.Message)"
        }
        
        # Additional error context
        if ($_.CategoryInfo) {
            Write-ScriptLog -LogFilePath $LogFile -Message "Error Category: $($_.CategoryInfo.Category)"
            Write-ScriptLog -LogFilePath $LogFile -Message "Error Reason: $($_.CategoryInfo.Reason)"
        }
        
        return $false
    }
    finally {
        Write-ScriptLog -LogFilePath $LogFile -Message "=== Scheduled Task Execution Complete ==="
    }
}

# Script Variables
$ScriptVersion = "1.9.2"
$ScriptReleaseDate = "2025-10-14"

# FileZ URL configuration
$DellBIOSConfigToolURL = "https://ftzr.zbox.filez.com/v2/delivery/data/fc2cbce165d54578b7c1e1d6fa1dcee0"
$LenovoBIOSConfigToolURL = "https://ftzr.zbox.filez.com/v2/delivery/data/fc2cbce165d54578b7c1e1d6fa1dcee0"

# BIOS files list
$script:DellCCTKFileLists = @("ABI.dll","BIOSIntf.dll","cctk.exe","cctk_x86_64_winpe_10.bat","cctk_x86_64_winpe_11.bat","dchapi64.dll","dchbas64.dll","libcrypto.dll","libcrypto-1_1-x64.dll","libssl.dll","libssl-1_1-x64.dll")
$script:LenovoBIOSConfigFileLists = @("ThinkBiosConfig.hta")

# Initialization logs file with computer name
$HostName = (Get-CimInstance Win32_ComputerSystem).Name
$LogFile = Initialize-LogFile -LogDirectory $LogsPath

# Log script initialization with detailed environment information
Write-ScriptLog -LogFilePath $LogFile -Message "<><><><><><><><><><><><><><><><><><><><><><><><>"
Write-ScriptLog -LogFilePath $LogFile -Message "=== MJC EnableBitLocker Program ==="
Write-ScriptLog -LogFilePath $LogFile -Message "=== EnableBitLocker.ps1 Script Started ==="
Write-ScriptLog -LogFilePath $LogFile -Message "Version: $ScriptVersion"
Write-ScriptLog -LogFilePath $LogFile -Message "Release Date: $ScriptReleaseDate"
Write-ScriptLog -LogFilePath $LogFile -Message "Execution Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-ScriptLog -LogFilePath $LogFile -Message "Computer Name: $HostName"
Write-ScriptLog -LogFilePath $LogFile -Message "Current User: $env:USERNAME"
Write-ScriptLog -LogFilePath $LogFile -Message "PowerShell Version: $($PSVersionTable.PSVersion)"
Write-ScriptLog -LogFilePath $LogFile -Message "Operating System: $((Get-CimInstance Win32_OperatingSystem).Caption)"
Write-ScriptLog -LogFilePath $LogFile -Message "OS Version: $((Get-CimInstance Win32_OperatingSystem).Version)"
Write-ScriptLog -LogFilePath $LogFile -Message "Log File Path: $LogFile"
Write-ScriptLog -LogFilePath $LogFile -Message "Script Parameters:"
Write-ScriptLog -LogFilePath $LogFile -Message "  - LogsPath: $LogsPath"
Write-ScriptLog -LogFilePath $LogFile -Message "  - LocalSharedPath: $LocalSharedPath"
Write-ScriptLog -LogFilePath $LogFile -Message "  - RemoteSharedPath: $RemoteSharedPath"
Write-ScriptLog -LogFilePath $LogFile -Message "  - DefaultDownloadPath: $DefaultDownloadPath"
Write-ScriptLog -LogFilePath $LogFile -Message "================================================"
Write-ScriptLog -LogFilePath $LogFile -Message "<><><><><><><><><><><><><><><><><><><><><><><><>"


# ========================================================================================================
# MAIN EXECUTION FLOW - BitLocker Enablement and SecureBoot Configuration
# ========================================================================================================

# --------------------------------------------------------------------------------------------------------
# STEP 0: TPM Compatibility Check
# --------------------------------------------------------------------------------------------------------
# Purpose: Check if TPM is available and compatible before proceeding with BitLocker operations
# If TPM is not available or not compatible, exit the script
# --------------------------------------------------------------------------------------------------------
Write-ScriptLog -LogFilePath $LogFile -Message "=== STEP 0: Checking TPM Compatibility ==="

        try {
            $tpmStatus = Get-Tpm -ErrorAction SilentlyContinue
    
    if (-not $tpmStatus) {
        Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] Unable to retrieve TPM status. TPM may not be supported on this system."
        Write-ScriptLog -LogFilePath $LogFile -Message "[EXIT] Script terminated due to TPM compatibility issues."
        exit 2
    }
    
    if (-not $tpmStatus.TpmPresent) {
        Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] TPM is not present on this system. BitLocker requires a compatible TPM security device."
        Write-ScriptLog -LogFilePath $LogFile -Message "[EXIT] Script terminated - No compatible Trusted Platform Module (TPM) security device found."
        exit 2
    }
    
    if (-not $tpmStatus.TpmEnabled) {
        Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] TPM is present but not enabled. Please enable TPM in BIOS/UEFI settings."
        Write-ScriptLog -LogFilePath $LogFile -Message "[EXIT] Script terminated - TPM is not enabled."
        exit 2
    }
    
    if (-not $tpmStatus.TpmActivated) {
        Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] TPM is enabled but not activated. Please activate TPM in BIOS/UEFI settings."
        Write-ScriptLog -LogFilePath $LogFile -Message "[EXIT] Script terminated - TPM is not activated."
        exit 2
    }
    
    if (-not $tpmStatus.TpmReady) {
        Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] TPM is present but not ready (Enabled: $($tpmStatus.TpmEnabled), Activated: $($tpmStatus.TpmActivated))."
        Write-ScriptLog -LogFilePath $LogFile -Message "[EXIT] Script terminated - TPM is not ready for BitLocker operations."
        exit 2
    }
    
    Write-ScriptLog -LogFilePath $LogFile -Message "[SUCCESS] TPM compatibility check passed:"
    Write-ScriptLog -LogFilePath $LogFile -Message "  - TPM Present: $($tpmStatus.TpmPresent)"
    Write-ScriptLog -LogFilePath $LogFile -Message "  - TPM Enabled: $($tpmStatus.TpmEnabled)"
    Write-ScriptLog -LogFilePath $LogFile -Message "  - TPM Activated: $($tpmStatus.TpmActivated)"
    Write-ScriptLog -LogFilePath $LogFile -Message "  - TPM Ready: $($tpmStatus.TpmReady)"
    
} catch {
    Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] Exception occurred during TPM compatibility check: $($_.Exception.Message)"
    Write-ScriptLog -LogFilePath $LogFile -Message "[EXIT] Script terminated due to TPM check failure."
    exit 2
}

# --------------------------------------------------------------------------------------------------------
# STEP 1: BitLocker Protection Status Check
# --------------------------------------------------------------------------------------------------------
# Purpose: Check if all drives are already protected by BitLocker
# If all drives are protected, enable auto-unlock for data drives and exit
# --------------------------------------------------------------------------------------------------------
Write-ScriptLog -LogFilePath $LogFile -Message "=== STEP 1: Checking BitLocker Protection Status ==="

$bitlockerStatus = Test-BitLockerProtection

if ($bitlockerStatus.AllProtected) {
    Write-ScriptLog -LogFilePath $LogFile -Message "All partitions are protected by BitLocker. Checking auto-unlock status for non-C drives."
    
    # ----------------------------------------------------------------------------------------------------
    # LOCKED DATA DRIVES REMEDIATION (Unlock with saved recovery key, then enable Auto-Unlock)
    # ----------------------------------------------------------------------------------------------------
    $lockedProcessed = 0
    $lockedUnlocked = 0
    $lockedUnlockFailed = 0
    $lockedAutoUnlockEnabled = 0
    
    $dataVolumes = Get-BitLockerVolume | Where-Object { $_.VolumeType -eq 'Data' -and $_.MountPoint -match '^[A-Z]:$' -and $_.MountPoint -ne 'C:' }
    foreach ($dv in $dataVolumes) {
        $mp = $dv.MountPoint
        try {
            $refresh = Get-ManageBdeStatusInfo -MountPoint $mp -LogFile $LogFile
            $lockText = $refresh.LockStatus
            $isLocked = ($lockText -and ($lockText -match 'Locked' -or $lockText -match '已锁定'))
            if ($isLocked) {
                $lockedProcessed++
                Write-ScriptLog -LogFilePath $LogFile -Message "[LOCKED] Detected locked data drive $mp (manage-bde: $lockText). Attempting unlock with recovery key..."
                $ok = Unlock-DataDriveIfLocked -MountPoint $mp
                if ($ok) {
                    $lockedUnlocked++
                    Write-ScriptLog -LogFilePath $LogFile -Message "[LOCKED] $mp unlocked successfully; enabling Auto-Unlock"
                    $au = Enable-DataDriveAutoUnlock -MountPoint $mp
                    if ($au) { $lockedAutoUnlockEnabled++ }
                } else {
                    $lockedUnlockFailed++
                    Write-ScriptLog -LogFilePath $LogFile -Message "[LOCKED] Failed to unlock $mp using recovery key; Auto-Unlock skipped"
                }
            }
        } catch {
            Write-ScriptLog -LogFilePath $LogFile -Message "[LOCKED CHECK ERROR] Failed to check/handle locked state for $mp : $($_.Exception.Message)"
        }
    }
    if ($lockedProcessed -gt 0) {
        Write-ScriptLog -LogFilePath $LogFile -Message "[LOCKED SUMMARY] Processed: $lockedProcessed, Unlocked: $lockedUnlocked, UnlockFailed: $lockedUnlockFailed, AutoUnlockEnabled: $lockedAutoUnlockEnabled"
    }
    
    # ====================================================================================================
    # AUTO-UNLOCK CONFIGURATION FOR DATA DRIVES
    # ====================================================================================================
    # Purpose: Enable auto-unlock for BitLocker-protected data drives (non-C drives)
    # This allows data drives to be automatically unlocked when the system boots
    # ====================================================================================================
    
    $allDrives = Get-BitLockerVolume | Where-Object { 
        $_.VolumeType -eq 'Data' -and 
        $_.MountPoint -ne "C:" -and 
        $_.MountPoint -match "^[A-Z]:$" -and 
        $_.ProtectionStatus -eq "On" -and 
        $_.VolumeStatus -eq 'FullyEncrypted'
    }
    
    # Initialize auto-unlock statistics
    $autoUnlockProcessed = 0
    $autoUnlockEnabled = 0
    $autoUnlockSkipped = 0
    
    Write-ScriptLog -LogFilePath $LogFile -Message "Found $($allDrives.Count) BitLocker-protected data drives to process for auto-unlock"

    if ($allDrives.Count -eq 0) {
        Write-ScriptLog -LogFilePath $LogFile -Message "[AUTO-UNLOCK INFO] No eligible data drives found for auto-unlock (require FullyEncrypted & ProtectionStatus=On). Skipping auto-unlock phase."
    }
    
    foreach ($drive in $allDrives) {
        $normalizedDrive = $drive.MountPoint
        $autoUnlockProcessed++
        
        try {
            Write-ScriptLog -LogFilePath $LogFile -Message "[AUTO-UNLOCK CHECK] Checking auto-unlock status for BitLocker-enabled drive $normalizedDrive"
            
            # Check if auto-unlock is already enabled
            if ($drive.AutoUnlockEnabled) {
                Write-ScriptLog -LogFilePath $LogFile -Message "[AUTO-UNLOCK SKIP] Auto-unlock already enabled for drive $normalizedDrive"
                $autoUnlockSkipped++
                continue
            }
            
            # Try to enable auto-unlock for BitLocker-enabled drives (wait until OS drive is protected)
            $enabled = Enable-DataDriveAutoUnlock -MountPoint $normalizedDrive
            if ($enabled) {
                $autoUnlockEnabled++
            } else {
                Write-ScriptLog -LogFilePath $LogFile -Message "[WARNING] Auto-unlock enable failed for $normalizedDrive"
            }
        } catch {
            Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] Failed to process auto-unlock for $normalizedDrive. Error: $_"
        }
    }
    
    # Log auto-unlock summary statistics
    Write-ScriptLog -LogFilePath $LogFile -Message "[AUTO-UNLOCK SUMMARY] Processed: $autoUnlockProcessed drives, Enabled: $autoUnlockEnabled, Already enabled: $autoUnlockSkipped"
    
    # ====================================================================================================
    # TEMPORARY FOLDER CLEANUP
    # ====================================================================================================
    # Purpose: Clean up temporary folders created during script execution
    # This ensures no temporary files are left behind after script completion
    # ====================================================================================================
    
    Write-ScriptLog -LogFilePath $LogFile -Message "Starting temporary folder cleanup process"
    
    $clearTempPath = Join-Path -Path $env:TEMP -ChildPath "BitLockerTemp"
    $clearDeployPath = Join-Path -Path $env:TEMP -ChildPath "BitLockerDeploy"
    
    # Check and delete BitLockerTemp folder
    if (Test-Path -Path $clearTempPath -PathType Container) {
        try {
            Remove-Item -Path $clearTempPath -Recurse -Force -ErrorAction Stop
            Write-ScriptLog -LogFilePath $LogFile -Message "Temporary folder '$clearTempPath' and its contents have been successfully deleted."
        } catch {
            Write-ScriptLog -LogFilePath $LogFile -Message "[WARNING] Failed to delete temporary folder '$clearTempPath': $_"
        }
    }
    
    # Check and delete BitLockerDeploy folder
    if (Test-Path -Path $clearDeployPath -PathType Container) {
        try {
            Remove-Item -Path $clearDeployPath -Recurse -Force -ErrorAction Stop
            Write-ScriptLog -LogFilePath $LogFile -Message "Temporary folder '$clearDeployPath' and its contents have been successfully deleted."
        } catch {
            Write-ScriptLog -LogFilePath $LogFile -Message "[WARNING] Failed to delete temporary folder '$clearDeployPath': $_"
        }
    }
    
    # ====================================================================================================
    # SCRIPT COMPLETION - ALL DRIVES PROTECTED
    # ====================================================================================================
    # All partitions are protected, log completion and exit script with success status
    # ====================================================================================================
    
    Write-ScriptLog -LogFilePath $LogFile -Message "=== All BitLocker Operations Complete ==="
    Write-ScriptLog -LogFilePath $LogFile -Message "=== EnableBitLocker.ps1(Version $ScriptVersion Release $ScriptReleaseDate) Script Execution Finished ==="
    exit 0  
    
} else {
    # ====================================================================================================
    # UNPROTECTED DRIVES DETECTED
    # ====================================================================================================
    # Some drives are not protected by BitLocker, continue with enablement process
    # ====================================================================================================
    
    $partitionsNames = $bitlockerStatus.UnprotectedDrives -join ", "
    Write-ScriptLog -LogFilePath $LogFile -Message "Partitions [$partitionsNames] are not protected by BitLocker. Continuing with enablement process."

    # ----------------------------------------------------------------------------------------------------
    # LOCKED DATA DRIVES REMEDIATION (Unprotected path)
    # ----------------------------------------------------------------------------------------------------
    # Context: After reboot or interruption, data volumes may be BitLocker-protected but locked, causing
    #          cmdlets to report Unknown/Locked. Before proceeding to certificate checks, attempt to
    #          unlock with local recovery key, then enable Auto-Unlock gated by OS protection.
    # ----------------------------------------------------------------------------------------------------
    Write-ScriptLog -LogFilePath $LogFile -Message "[REMEDIATION] Checking for locked data drives due to reboot/interruption"

    $lockedProcessed = 0
    $lockedUnlocked = 0
    $lockedUnlockFailed = 0
    $lockedAutoUnlockEnabled = 0

    $dataVolumes = Get-BitLockerVolume | Where-Object { $_.VolumeType -eq 'Data' -and $_.MountPoint -match '^[A-Z]:$' -and $_.MountPoint -ne 'C:' }
    foreach ($dv in $dataVolumes) {
        $mp = $dv.MountPoint
        try {
            $refresh = Get-ManageBdeStatusInfo -MountPoint $mp -LogFile $LogFile
            $lockText = $refresh.LockStatus
            $isLocked = $false
            if ($dv.LockStatus -eq 'Locked') { $isLocked = $true }
            elseif ($lockText -and ($lockText -match 'Locked' -or $lockText -match '已锁定')) { $isLocked = $true }
            elseif ($dv.ProtectionStatus -eq 'Unknown' -and $lockText) { $isLocked = ($lockText -match 'Locked' -or $lockText -match '已锁定') }

            if ($isLocked) {
                $lockedProcessed++
                Write-ScriptLog -LogFilePath $LogFile -Message "[LOCKED] Detected locked data drive $mp; attempting unlock with recovery key..."
                $ok = Unlock-DataDriveIfLocked -MountPoint $mp
                if ($ok) {
                    $lockedUnlocked++
                    Write-ScriptLog -LogFilePath $LogFile -Message "[LOCKED] $mp unlocked successfully; will enable Auto-Unlock after OS protection is satisfied"
                    $au = Enable-DataDriveAutoUnlock -MountPoint $mp
                    if ($au) { $lockedAutoUnlockEnabled++ }
                } else {
                    $lockedUnlockFailed++
                    Write-ScriptLog -LogFilePath $LogFile -Message "[LOCKED] Failed to unlock $mp using recovery key; Auto-Unlock skipped"
                }
            } else {
                # If not locked but Auto-Unlock disabled and drive protection is On, enable after OS gate
                if ($dv.ProtectionStatus -eq 'On' -and -not $dv.AutoUnlockEnabled) {
                    Write-ScriptLog -LogFilePath $LogFile -Message "[AUTO-UNLOCK INFO] $mp is accessible; enabling Auto-Unlock gated by OS protection"
                    $au = Enable-DataDriveAutoUnlock -MountPoint $mp
                    if ($au) { $lockedAutoUnlockEnabled++ }
                }
            }
        } catch {
            Write-ScriptLog -LogFilePath $LogFile -Message "[LOCKED CHECK ERROR] Failed to check/handle locked state for $mp : $($_.Exception.Message)"
        }
    }
    if ($lockedProcessed -gt 0) {
        Write-ScriptLog -LogFilePath $LogFile -Message "[LOCKED SUMMARY] Processed: $lockedProcessed, Unlocked: $lockedUnlocked, UnlockFailed: $lockedUnlockFailed, AutoUnlockEnabled: $lockedAutoUnlockEnabled"
    } else {
        Write-ScriptLog -LogFilePath $LogFile -Message "[REMEDIATION] No locked data drives detected in unprotected branch"
    }
}

# --------------------------------------------------------------------------------------------------------
# RESUME ENCRYPTION MONITORING AFTER REBOOT/INTERRUPTION (Skip Step 2 when ongoing)
# --------------------------------------------------------------------------------------------------------
# Context: If encryption has already started (e.g., previous run created BitLocker jobs), the system may
#          report ProtectionStatus=Off/Unknown while VolumeStatus shows EncryptionInProgress or manage-bde
#          reveals an active encryption method. In such cases, resume monitoring instead of re-entering
#          Step 2 enablement logic.
try {
    $resumeTargets = @()
    $dataVolumesResume = Get-BitLockerVolume | Where-Object { $_.VolumeType -eq 'Data' -and $_.MountPoint -match '^[A-Z]:$' -and $_.MountPoint -ne 'C:' }
    foreach ($dv in $dataVolumesResume) {
        $mp = $dv.MountPoint
        $info = $null
        try { $info = Get-ManageBdeStatusInfo -MountPoint $mp -LogFile $LogFile } catch { $info = $null }
        $isEncrypting = $false
        if ($dv.VolumeStatus -eq 'EncryptionInProgress' -or $dv.VolumeStatus -eq 'EncryptionPaused') { $isEncrypting = $true }
        elseif ($info -and $info.ConversionStatus -and ($info.ConversionStatus -match 'Encryption' -or $info.ConversionStatus -match '加密')) { $isEncrypting = $true }
        elseif ($info -and $info.EncryptionMethod -and -not ($info.EncryptionMethod -match 'None' -or $info.EncryptionMethod -match '无')) { $isEncrypting = $true }
        if ($isEncrypting) { $resumeTargets += $mp }
    }
    # Also treat OS encryption in progress as a resume indicator
    $osVol = Get-BitLockerVolume | Where-Object { $_.MountPoint -eq 'C:' }
    $osEncrypting = ($osVol -and ($osVol.VolumeStatus -eq 'EncryptionInProgress' -or $osVol.VolumeStatus -eq 'EncryptionPaused'))
    if ($osEncrypting -and $resumeTargets.Count -eq 0) {
        # If OS is encrypting but data volumes are reported Unknown by cmdlets, include data volumes
        foreach ($dv in $dataVolumesResume) { $resumeTargets += $dv.MountPoint }
        $resumeTargets = $resumeTargets | Select-Object -Unique
    }

    if ($resumeTargets.Count -gt 0) {
        Write-ScriptLog -LogFilePath $LogFile -Message "[RESUME] Ongoing BitLocker encryption detected; starting monitoring for data drive(s): $($resumeTargets -join ', ')"
        foreach ($mp in $resumeTargets) {
            Write-ScriptLog -LogFilePath $LogFile -Message "[MONITOR START] Starting encryption monitoring for $mp"
            $ok = $false
            try {
                $ok = Watch-BitLockerStatus -MountPoint $mp -IntervalSeconds 30 -TimeoutSeconds 21600 -LogFile $LogFile
            } catch {
                Write-ScriptLog -LogFilePath $LogFile -Message "[MONITOR ERROR] Failed monitoring for $mp : $($_.Exception.Message)"
            }
            if ($ok) {
                Write-ScriptLog -LogFilePath $LogFile -Message "[MONITOR COMPLETE] $mp - Encryption completed and protection is On"
            } else {
                Write-ScriptLog -LogFilePath $LogFile -Message "[MONITOR TIMEOUT] $mp - Monitoring timed out or ended; encryption may still be in progress"
            }
        }
        Write-ScriptLog -LogFilePath $LogFile -Message "=== BitLocker Encryption Monitoring Complete ==="
        Write-ScriptLog -LogFilePath $LogFile -Message "=== EnableBitLocker.ps1(Version $ScriptVersion Release $ScriptReleaseDate) Script Execution Finished ==="
        exit 0
    }
} catch {
    Write-ScriptLog -LogFilePath $LogFile -Message "[RESUME ERROR] Failed to evaluate resume monitoring branch: $($_.Exception.Message)"
}

# --------------------------------------------------------------------------------------------------------
# STEP 2: UEFI CA 2023 Certificate Check and BitLocker Enablement
# --------------------------------------------------------------------------------------------------------
# Purpose: Check if Windows UEFI CA 2023 certificate is installed
# If certificate exists, enable BitLocker directly on unprotected drives
# --------------------------------------------------------------------------------------------------------
Write-ScriptLog -LogFilePath $LogFile -Message "=== STEP 2: Checking UEFI CA 2023 Certificate Status ==="

if (Test-WindowsUEFICA2023) {
    # ====================================================================================================
    # CERTIFICATE FOUND - DIRECT BITLOCKER ENABLEMENT
    # ====================================================================================================
    # Windows UEFI CA 2023 certificate is installed, proceed with BitLocker enablement
    # ====================================================================================================
    
Write-ScriptLog -LogFilePath $LogFile -Message "Windows UEFI CA 2023 certificate is already installed. Enabling BitLocker on unprotected drives."
    
    # ====================================================================================================
    # DRIVE CATEGORIZATION FOR PROCESSING
    # ====================================================================================================
    # Separate system drive (C:) and data drives for different processing approaches
    # System drive uses serial processing for stability
    # Data drives use parallel processing for efficiency
    # ====================================================================================================
    
    # Read deferred retry marks (if any) and merge with current unprotected list (minimal change)
    $retryFilePath = Join-Path $env:ProgramData 'BitLocker\Retry.json'
    $retryDrives = @()
    if (Test-Path -Path $retryFilePath -PathType Leaf) {
        try {
            $retryContent = Get-Content -Path $retryFilePath -ErrorAction Stop | Out-String
            $retryJson = $retryContent | ConvertFrom-Json
            if ($retryJson -and $retryJson.Drives) {
                $retryDrives = @($retryJson.Drives) | ForEach-Object { ($_.Trim().TrimEnd(':') + ":") }
                Write-ScriptLog -LogFilePath $LogFile -Message "[RETRY MARK] Loaded deferred retry targets: $($retryDrives -join ', ')"
            }
        } catch {
            Write-ScriptLog -LogFilePath $LogFile -Message "[RETRY MARK WARNING] Failed to read retry mark file: $($_.Exception.Message)"
        }
    }
    $unprotectedUnion = (@($bitlockerStatus.UnprotectedDrives) + $retryDrives) | Where-Object { $_ } | Select-Object -Unique
    
    $systemDrives = $unprotectedUnion | Where-Object { 
        ($_.Trim().TrimEnd(':') + ":") -eq "C:" 
    }
    $dataDrives = $unprotectedUnion | Where-Object { 
        ($_.Trim().TrimEnd(':') + ":") -ne "C:" 
    }
    
    # Flags for deferred retry post SecureBoot update
    $NeedsRetryPostSecureBoot = $false
    $FailedDriveLetters = @()
    
    $allBitlockerInfo = @()
    
    # ====================================================================================================
    # SYSTEM DRIVE (C:) PROCESSING - SERIAL MODE
    # ====================================================================================================
    # Process C: drive using serial processing for maximum stability
    # System drive encryption requires careful handling to avoid boot issues
    # ====================================================================================================
    
    if ($systemDrives.Count -gt 0) {
        Write-ScriptLog -LogFilePath $LogFile -Message "[SYSTEM DRIVE] Processing system drive (C:) using serial processing for stability"
        
        try {
            $systemBitlockerInfo = Enable-UnprotectedDrives -UnprotectedDrives $systemDrives -RecoveryKeyPath $RecoveryKeyPath -LogFile $LogFile
            if ($systemBitlockerInfo) {
                $allBitlockerInfo += $systemBitlockerInfo
                Write-ScriptLog -LogFilePath $LogFile -Message "[SUCCESS] System drive BitLocker enablement completed"
            }
        } catch {
            Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] Failed to enable BitLocker on system drive: $($_.Exception.Message)"
        }
    }
    
    # ====================================================================================================
    # DATA DRIVES PROCESSING - PARALLEL MODE
    # ====================================================================================================
    # Process data drives using parallel processing for improved performance
    # Includes fallback to serial processing if parallel mode encounters issues
    # ====================================================================================================
    
    if ($dataDrives.Count -gt 0) {
        Write-ScriptLog -LogFilePath $LogFile -Message "[DATA DRIVES] Processing $($dataDrives.Count) data drive(s) using parallel processing for efficiency"
        
        try {
            $dataBitlockerInfo = Enable-ParallelBitLocker -UnprotectedDrives $dataDrives -RecoveryKeyPath $RecoveryKeyPath -LogFile $LogFile
            if ($dataBitlockerInfo) {
                $allBitlockerInfo += $dataBitlockerInfo
                Write-ScriptLog -LogFilePath $LogFile -Message "[SUCCESS] Data drives parallel BitLocker enablement completed"
            }
        } catch {
            $errorMessage = $_.Exception.Message
            
            # ========================================================================================
            # ERROR HANDLING - USER INTERACTIVE MODE
            # ========================================================================================
            # Check if error is related to UserInteractive mode (common in GPO/Task Scheduler)
            # This is expected behavior and should not block the process
            # ========================================================================================
            
            $isUserInteractiveError = $false
            foreach ($uiErrorKeyword in $SCRIPT_CONSTANTS.ERROR_USERINTERACTIVE) {
                if ($errorMessage -like "*$uiErrorKeyword*") {
                    $isUserInteractiveError = $true
                    break
                }
            }
            
            if ($isUserInteractiveError) {
                Write-ScriptLog -LogFilePath $LogFile -Message "[WARNING] UserInteractive mode error detected in parallel processing: $errorMessage"
                Write-ScriptLog -LogFilePath $LogFile -Message "[INFO] This is expected behavior when running in non-interactive mode (GPO/Task Scheduler)"
                
                # Attempt to recover partial results from parallel processing
                try {
                    Write-ScriptLog -LogFilePath $LogFile -Message "[RECOVERY] Waiting for potential parallel job completion..."
                    Start-Sleep -Seconds 5
                    
                    $dataBitlockerInfo = Enable-ParallelBitLocker -UnprotectedDrives $dataDrives -RecoveryKeyPath $RecoveryKeyPath -LogFile $LogFile
                    if ($dataBitlockerInfo) {
                        $allBitlockerInfo += $dataBitlockerInfo
                        Write-ScriptLog -LogFilePath $LogFile -Message "[SUCCESS] Recovered data from parallel processing"
                    }
                } catch {
                    Write-ScriptLog -LogFilePath $LogFile -Message "[FALLBACK] Parallel processing recovery failed, switching to serial processing for data drives"
                    
                    $dataBitlockerInfo = Enable-UnprotectedDrives -UnprotectedDrives $dataDrives -LogFile $LogFile
                    if ($dataBitlockerInfo) {
                        $allBitlockerInfo += $dataBitlockerInfo
                        Write-ScriptLog -LogFilePath $LogFile -Message "[SUCCESS] Data drives serial processing completed as fallback"
                    }
                }
            } else {
                # ========================================================================================
                # ERROR HANDLING - OTHER ERRORS
                # ========================================================================================
                # For non-UserInteractive errors, fall back to serial processing immediately
                # ========================================================================================
                
                Write-ScriptLog -LogFilePath $LogFile -Message "[FALLBACK] Parallel processing failed with error: $errorMessage"
                Write-ScriptLog -LogFilePath $LogFile -Message "[FALLBACK] Switching to serial processing for data drives"
                
                $dataBitlockerInfo = Enable-UnprotectedDrives -UnprotectedDrives $dataDrives -LogFile $LogFile
                if ($dataBitlockerInfo) {
                    $allBitlockerInfo += $dataBitlockerInfo
                    Write-ScriptLog -LogFilePath $LogFile -Message "[SUCCESS] Data drives serial processing completed as fallback"
                }
            }
        }
    }
    
    # ====================================================================================================
    # BITLOCKER ENABLEMENT RESULTS PROCESSING
    # ====================================================================================================
    # Process and analyze BitLocker enablement results
    # Handle successful, partial, and failed drive encryption attempts
    # ====================================================================================================
    
    $bitlockerInfo = $allBitlockerInfo
    #Start-RandomSleep -Min 10 -Max 36
    
    Write-ScriptLog -LogFilePath $LogFile -Message "Processing BitLocker enablement results for $($bitlockerInfo.Count) drive(s)"
    
    if ($null -ne $bitlockerInfo -and $bitlockerInfo.Count -gt 0) {
        # Categorize results by status
        $successfulDrives = $bitlockerInfo | Where-Object { $_.Status -eq "Success" -and ($_.SubmittedToForms -ne $true) }
        $partialSuccessDrives = $bitlockerInfo | Where-Object { $_.Status -eq "PartialSuccess" }
        $failedDrives = $bitlockerInfo | Where-Object { $_.Status -eq "Failed" }
        
        # ========================================================================================
        # SUCCESSFUL DRIVES - RECOVERY KEY HANDLING
        # ========================================================================================
        # Handle recovery key data for successfully encrypted drives
        # ========================================================================================
        
        if ($successfulDrives.Count -gt 0) {
            Write-ScriptLog -LogFilePath $LogFile -Message "[SUCCESS] Processing $($successfulDrives.Count) successfully encrypted drive(s)"
            
            foreach ($drive in $successfulDrives) {
                # Submission is disabled
                # [SUBMISSION DISABLED] Skip external submission call and continue
                # Write-ScriptLog -LogFilePath $LogFile -Message "[SUBMISSION SKIPPED] External submission is disabled for drive $($drive.Drive)"
                $drive.SubmittedToForms = $false
            }
            Write-ScriptLog -LogFilePath $LogFile -Message "[SUMMARY] BitLocker successfully enabled on $($successfulDrives.Count) drive(s). External submission is currently disabled."
        }
        
        # ========================================================================================
        # PARTIAL SUCCESS DRIVES - ENCRYPTION STARTED
        # ========================================================================================
        # Handle drives where encryption started but recovery key retrieval failed
        # ========================================================================================
        
        if ($partialSuccessDrives.Count -gt 0) {
            Write-ScriptLog -LogFilePath $LogFile -Message "[PARTIAL SUCCESS] BitLocker partially enabled on $($partialSuccessDrives.Count) drive(s) (encryption started but recovery key retrieval failed)"
            
            foreach ($drive in $partialSuccessDrives) {
                Write-ScriptLog -LogFilePath $LogFile -Message "[PARTIAL] Drive $($drive.Drive): BitLocker enabled but recovery key not available - $($drive.ErrorMessage)"
            }
        }
        
        # ========================================================================================
        # FAILED DRIVES - ERROR ANALYSIS
        # ========================================================================================
        # Analyze and report failed BitLocker enablement attempts
        # Include disk space checks and detailed error reporting
        # ========================================================================================
        
        if ($failedDrives.Count -gt 0) {
            Write-ScriptLog -LogFilePath $LogFile -Message "[FAILED] Failed to enable BitLocker on $($failedDrives.Count) drive(s)"
            
            foreach ($failed in $failedDrives) {
                $errorMessage = if ([string]::IsNullOrEmpty($failed.ErrorMessage)) { "Unknown error" } else { $failed.ErrorMessage }
                Write-ScriptLog -LogFilePath $LogFile -Message "[FAILED] Drive $($failed.Drive) failed: $errorMessage"
                
                # Check disk space sufficiency
                try {
                    $freeSpace = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='$($failed.Drive)'" | Select-Object -ExpandProperty FreeSpace
                    if ($null -ne $freeSpace -and $freeSpace -lt 100MB) {
                        Write-ScriptLog -LogFilePath $LogFile -Message "[DISK SPACE] Insufficient disk space on drive $($failed.Drive). At least 100MB is required for BitLocker"
                    }
                } catch {
                    Write-ScriptLog -LogFilePath $LogFile -Message "[DISK SPACE] Unable to check free space for drive $($failed.Drive)"
                }
            }
            
            # ========================================================================================
            # SHORT RETRY FOR TRANSIENT ERRORS (no volume release or service stops)
            # ========================================================================================
            if ($successfulDrives.Count -eq 0 -and $partialSuccessDrives.Count -eq 0) {
                $transientKeywords = @(
                    'UserInteractive',
                    'non-interactive',
                    'Task Scheduler',
                    'volume is busy',
                    'in use',
                    'cannot lock',
                    'restart required',
                    'pending reboot'
                )
                $retryCandidates = @()
                foreach ($fd in $failedDrives) {
                    $msg = $fd.ErrorMessage
                    foreach ($kw in $transientKeywords) {
                        if ($msg -like "*${kw}*") { $retryCandidates += $fd; break }
                    }
                }
                if ($retryCandidates.Count -gt 0) {
                    Write-ScriptLog -LogFilePath $LogFile -Message "[RETRY] Planning short retry for $($retryCandidates.Count) drive(s) due to transient errors"
                    #Start-RandomSleep -Min 10 -Max 30
                    
                    $retryList = $retryCandidates | Select-Object -ExpandProperty Drive
                    $retrySystem = $retryList | Where-Object { ($_.Trim().TrimEnd(':') + ":") -eq "C:" }
                    $retryData   = $retryList | Where-Object { ($_.Trim().TrimEnd(':') + ":") -ne "C:" }
                    
                    $retryResults = @()
                    try {
                        if ($retrySystem -and $retrySystem.Count -gt 0) {
                            Write-ScriptLog -LogFilePath $LogFile -Message "[RETRY SYSTEM] Retrying BitLocker enablement for system drive(s): $($retrySystem -join ', ')"
                            $sysRetry = Enable-UnprotectedDrives -UnprotectedDrives $retrySystem -RecoveryKeyPath $RecoveryKeyPath -LogFile $LogFile
                            if ($sysRetry) { $retryResults += $sysRetry }
                        }
                    } catch {
                        Write-ScriptLog -LogFilePath $LogFile -Message "[RETRY SYSTEM ERROR] $($_.Exception.Message)"
                    }
                    
                    try {
                        if ($retryData -and $retryData.Count -gt 0) {
                            Write-ScriptLog -LogFilePath $LogFile -Message "[RETRY DATA] Retrying BitLocker enablement for data drive(s): $($retryData -join ', ')"
                            try {
                                $dataRetry = Enable-ParallelBitLocker -UnprotectedDrives $retryData -RecoveryKeyPath $RecoveryKeyPath -LogFile $LogFile
                                if ($dataRetry) { $retryResults += $dataRetry }
                            } catch {
                                Write-ScriptLog -LogFilePath $LogFile -Message "[RETRY DATA FALLBACK] Parallel retry failed: $($_.Exception.Message). Falling back to serial."
                                $dataRetrySerial = Enable-UnprotectedDrives -UnprotectedDrives $retryData -LogFile $LogFile
                                if ($dataRetrySerial) { $retryResults += $dataRetrySerial }
                            }
                        }
                    } catch {
                        Write-ScriptLog -LogFilePath $LogFile -Message "[RETRY DATA ERROR] $($_.Exception.Message)"
                    }
                    
                    if ($retryResults -and $retryResults.Count -gt 0) {
                        $allBitlockerInfo += $retryResults
                        $bitlockerInfo = $allBitlockerInfo
                        Write-ScriptLog -LogFilePath $LogFile -Message "[RETRY SUMMARY] Processed additional $($retryResults.Count) result(s) from short retry"
                        
                        # Re-categorize after retry
                        $successfulDrives = $bitlockerInfo | Where-Object { $_.Status -eq "Success" }
                        $partialSuccessDrives = $bitlockerInfo | Where-Object { $_.Status -eq "PartialSuccess" }
                        $failedDrives = $bitlockerInfo | Where-Object { $_.Status -eq "Failed" }
                    }
                }
            }
            
            # If still no success after retry, mark for deferred retry post SecureBoot update
            if ($successfulDrives.Count -eq 0 -and $partialSuccessDrives.Count -eq 0) {
                $NeedsRetryPostSecureBoot = $true
                $FailedDriveLetters = $failedDrives | Select-Object -ExpandProperty Drive
                Write-ScriptLog -LogFilePath $LogFile -Message "[DEFERRED RETRY] Marked drives for post-SecureBoot retry: $($FailedDriveLetters -join ', ')"
            }
        }
        
        # ========================================================================================
        # SUCCESS CHECK AND EARLY EXIT
        # ========================================================================================
        # If all drives were successfully processed, exit script with success
        # SecureBoot update is not necessary when BitLocker is successfully enabled on all targets
        # ========================================================================================
        
        if ($successfulDrives.Count -eq 0 -and $partialSuccessDrives.Count -eq 0) {
            Write-ScriptLog -LogFilePath $LogFile -Message "[RESULT] No drives were successfully encrypted"
        }
        
        $allSucceeded = ($partialSuccessDrives.Count -eq 0 -and $failedDrives.Count -eq 0 -and $successfulDrives.Count -gt 0)
        if ($allSucceeded) {
            Write-ScriptLog -LogFilePath $LogFile -Message "[SUCCESS] All target drives successfully encrypted. SecureBoot update process is not necessary."
            Write-ScriptLog -LogFilePath $LogFile -Message "=== BitLocker Operations Complete - Exiting with Success ==="
            exit 0
        }
        
        # ----------------------------------------------------------------------------------------
        # FINAL GUARD: Confirm overall BitLocker protection and short-circuit if all protected
        # Rationale: Some result objects may not reflect final states immediately. A fresh check
        # ensures we skip SecureBoot processing when all partitions are protected post enablement.
        # ----------------------------------------------------------------------------------------
        try {
            $postStatusCheck = Test-BitLockerProtection
            if ($postStatusCheck -and $postStatusCheck.AllProtected) {
                Write-ScriptLog -LogFilePath $LogFile -Message "[SUCCESS] BitLocker protection confirmed on all partitions. Skipping SecureBoot processing."
                Write-ScriptLog -LogFilePath $LogFile -Message "=== BitLocker Operations Complete - Exiting with Success ==="
                exit 0
            }
        } catch {
            Write-ScriptLog -LogFilePath $LogFile -Message "[WARNING] Post-enable protection check failed: $($_.Exception.Message)"
        }
        
    } else {
        # ====================================================================================================
        # NO BITLOCKER RESULTS RETURNED
        # ====================================================================================================
        # BitLocker enablement function did not return results, indicating failure
        # ====================================================================================================
        
        Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] Enable-UnprotectedDrives returned no results. BitLocker may have failed to enable on the drives."
        exit 1
    } 
    
} else {
    # ====================================================================================================
    # CERTIFICATE NOT FOUND - SECUREBOOT UPDATE REQUIRED
    # ====================================================================================================
    # Windows UEFI CA 2023 certificate is not installed
    # Need to update SecureBoot database to include the certificate
    # ====================================================================================================
    
    Write-ScriptLog -LogFilePath $LogFile -Message "Windows UEFI CA 2023 certificate is not installed. Continuing script to update SecureBoot database."
}

# --------------------------------------------------------------------------------------------------------
# STEP 3: SecureBoot Status Check and OEM-Specific Processing
# --------------------------------------------------------------------------------------------------------
# Purpose: Check SecureBoot status and handle OEM-specific BIOS configuration
# Different OEM manufacturers require different tools and approaches
# --------------------------------------------------------------------------------------------------------
Write-ScriptLog -LogFilePath $LogFile -Message "=== STEP 3: Checking SecureBoot Status and OEM Processing ==="

if (Get-SecureBootStatus) {
    # ====================================================================================================
    # SECUREBOOT ENABLED - DIRECT DATABASE UPDATE
    # ====================================================================================================
    # SecureBoot is already enabled, proceed with database update
    # ====================================================================================================
    
Write-ScriptLog -LogFilePath $LogFile -Message "SecureBoot is already enabled. Proceeding with database update."
    
    # ====================================================================================================
    # REGISTRY CONFIGURATION UPDATE
    # ====================================================================================================
    # Update registry settings required for SecureBoot database update
    # ====================================================================================================
    
    $registryResult = Set-SecureBootRegistryConfiguration -LogFile $LogFile
    if ($registryResult) {
        Write-ScriptLog -LogFilePath $LogFile -Message "[SUCCESS] SecureBoot registry configuration updated successfully"
        
        # ========================================================================================
        # SECUREBOOT UPDATE TASK EXECUTION
        # ========================================================================================
        # Start the SecureBoot update task to apply database changes
        # ========================================================================================
        
        $taskResult = Start-SecureBootUpdateTask -LogFile $LogFile
        if ($taskResult) {
            Write-ScriptLog -LogFilePath $LogFile -Message "[SUCCESS] SecureBoot update task started successfully"
            # If previous enablement completely failed, create retry mark and exit with code 3
            if ($NeedsRetryPostSecureBoot -and $FailedDriveLetters -and $FailedDriveLetters.Count -gt 0) {
                try {
                    $retryDir = Join-Path $env:ProgramData 'BitLocker'
                    if (-not (Test-Path -Path $retryDir -PathType Container)) { New-Item -ItemType Directory -Path $retryDir | Out-Null }
                    $retryPayload = @{ Drives = $FailedDriveLetters; Timestamp = (Get-Date).ToString('s') } | ConvertTo-Json -Depth 3
                    Set-Content -Path (Join-Path $retryDir 'Retry.json') -Value $retryPayload -Encoding UTF8
                    Write-ScriptLog -LogFilePath $LogFile -Message "[RETRY MARK] Saved deferred retry targets to $retryDir\Retry.json"
                    Write-ScriptLog -LogFilePath $LogFile -Message "[EXIT] SecureBoot update initiated. Exiting with code 3 to defer BitLocker retry."
                    exit 3
                } catch {
                    Write-ScriptLog -LogFilePath $LogFile -Message "[RETRY MARK ERROR] Failed to save retry mark: $($_.Exception.Message)"
                }
            }
        } else {
            Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] Failed to start SecureBoot update task"
        }
    } else {
        Write-ScriptLog -LogFilePath $LogFile -Message "[ERROR] Failed to update SecureBoot registry configuration"
    }

} else {
    # ====================================================================================================
    # SECUREBOOT DISABLED - OEM-SPECIFIC ENABLEMENT
    # ====================================================================================================
    # SecureBoot is not enabled, need to enable it using OEM-specific tools
    # Different manufacturers require different approaches and tools
    # ====================================================================================================
    
    Write-ScriptLog -LogFilePath $LogFile -Message "SecureBoot is not enabled. Checking OEM information for manufacturer-specific enablement."
    
    $oemInfo = Get-OEMInfo
    Write-ScriptLog -LogFilePath $LogFile -Message "Detected OEM Manufacturer: $($oemInfo.Manufacturer)"
    
    # ====================================================================================================
    # DELL COMPUTER PROCESSING
    # ====================================================================================================
    # Dell computers use Dell Command | Configure (CCTK) tool for BIOS configuration
    # ====================================================================================================
    
    if ($oemInfo.Manufacturer -match "Dell") {
        Write-ScriptLog -LogFilePath $LogFile -Message "[DELL] Detected Dell computer. Starting Dell Command | Configure tool download and configuration."
        
        # ========================================================================================
        # TEMPORARY PATH CREATION
        # ========================================================================================
        # Create temporary folder for Dell CCTK tool files
        # ========================================================================================
        
        $tempPath = New-TempPath -FolderName "BitLockerTemp"
        
        # ========================================================================================
        # DOWNLOAD PATH DETERMINATION
        # ========================================================================================
        # Determine the best download source (local, remote, or URL)
        # ========================================================================================
        
        $downloadPath = Get-DownloadPath -LocalDownloadPath $LocalSharedPath `
                                        -RemoteDownloadPath $RemoteSharedPath `
                                        -DefaultDownloadPath $DefaultDownloadPath
        
        # ========================================================================================
        # DELL CCTK FILES ACQUISITION
        # ========================================================================================
        # Download or sync Dell CCTK tool files from the determined source
        # ========================================================================================
        
        if ($downloadPath.Type -eq "Local" -or $downloadPath.Type -eq "Remote") {
            # Sync files from shared network path
            $sharedPath = Join-Path -Path $downloadPath.Path -ChildPath "Dell"
            Write-ScriptLog -LogFilePath $LogFile -Message "[DELL] Syncing Dell CCTK files from shared path: $sharedPath"
            
            $syncResult = Sync-SharedFiles -SharePath $sharedPath `
                                          -FileList $script:DellCCTKFileLists `
                                          -LocalFolder $tempPath
            
            if ($syncResult.Success -ne $true) {
                Write-ScriptLog -LogFilePath $LogFile -Message "[DELL ERROR] Failed to sync Dell CCTK files from shared path: $sharedPath"
                return
            }
            Write-ScriptLog -LogFilePath $LogFile -Message "[DELL SUCCESS] Successfully synced Dell CCTK files from shared path"
            
        } else {
            # Download files from URL
            Write-ScriptLog -LogFilePath $LogFile -Message "[DELL] Downloading Dell CCTK files from URL: $DellBIOSConfigToolURL"
            
            foreach ($file in $script:DellCCTKFileLists) {
                $fileUrl = ($DellBIOSConfigToolURL, $file) -join "/"
                $downloadResult = Get-FileFromUrl -DownloadUrl $fileUrl `
                                                  -DestinationPath $tempPath `
                                                  -FileName $file 
                
                if ($downloadResult.Success -ne $true) {
                    Write-ScriptLog -LogFilePath $LogFile -Message "[DELL ERROR] Failed to download Dell CCTK file: $file. Error: $($downloadResult.Error)"
                    return
                }
                Write-ScriptLog -LogFilePath $LogFile -Message "[DELL SUCCESS] Successfully downloaded Dell CCTK file: $file"
            }
        }
        
        # ========================================================================================
        # DELL SECUREBOOT ENABLEMENT COMMANDS
        # ========================================================================================
        # Execute Dell CCTK commands to enable SecureBoot in BIOS
        # ========================================================================================
        
        $commands = @(
            "cctk --SecureBoot=Enabled"
        )
        
        Write-ScriptLog -LogFilePath $LogFile -Message "[DELL] Executing Dell CCTK commands to enable SecureBoot"
        
        foreach ($cmd in $commands) {
            try {
                Write-ScriptLog -LogFilePath $LogFile -Message "[DELL COMMAND] Executing: $cmd"
                
                if (-not (Invoke-ExternalCommand -WorkingDirectory $tempPath -Command $cmd)) {
                    Write-ScriptLog -LogFilePath $LogFile -Message "[DELL WARNING] Command failed: $cmd"
                    Write-ScriptLog -LogFilePath $LogFile -Message "[CONTINUE] Script will continue despite command failure"
                } else {
                    Write-ScriptLog -LogFilePath $LogFile -Message "[DELL SUCCESS] Command succeeded: $cmd"
                    
                    # ============================================================================
                    # POST-ENABLEMENT CONFIGURATION
                    # ============================================================================
                    # Execute registry configuration after successful SecureBoot enablement
                    # ============================================================================
                    
                    $registryResult = Set-SecureBootRegistryConfiguration -LogFile $LogFile
                    if ($registryResult) {
                        Write-ScriptLog -LogFilePath $LogFile -Message "[DELL SUCCESS] SecureBoot registry configuration updated successfully"
                        
                        # Start SecureBoot update task
                        $taskResult = Start-SecureBootUpdateTask -LogFile $LogFile
                        if ($taskResult) {
                            Write-ScriptLog -LogFilePath $LogFile -Message "[DELL SUCCESS] SecureBoot update task started successfully"
                            if ($NeedsRetryPostSecureBoot -and $FailedDriveLetters -and $FailedDriveLetters.Count -gt 0) {
                                try {
                                    $retryDir = Join-Path $env:ProgramData 'BitLocker'
                                    if (-not (Test-Path -Path $retryDir -PathType Container)) { New-Item -ItemType Directory -Path $retryDir | Out-Null }
                                    $retryPayload = @{ Drives = $FailedDriveLetters; Timestamp = (Get-Date).ToString('s') } | ConvertTo-Json -Depth 3
                                    Set-Content -Path (Join-Path $retryDir 'Retry.json') -Value $retryPayload -Encoding UTF8
                                    Write-ScriptLog -LogFilePath $LogFile -Message "[RETRY MARK] Saved deferred retry targets to $retryDir\Retry.json"
                                    Write-ScriptLog -LogFilePath $LogFile -Message "[EXIT] SecureBoot update initiated (Dell). Exiting with code 3 to defer BitLocker retry."
                                    exit 3
                                } catch {
                                    Write-ScriptLog -LogFilePath $LogFile -Message "[RETRY MARK ERROR] Failed to save retry mark: $($_.Exception.Message)"
                                }
                            }
                        } else {
                            Write-ScriptLog -LogFilePath $LogFile -Message "[DELL ERROR] Failed to start SecureBoot update task"
                        }
                    } else {
                        Write-ScriptLog -LogFilePath $LogFile -Message "[DELL ERROR] Failed to update SecureBoot registry configuration"
                    }
                }
            } catch {
                Write-ScriptLog -LogFilePath $LogFile -Message "[DELL ERROR] Exception during command execution: $cmd"
                Write-ScriptLog -LogFilePath $LogFile -Message "[DELL ERROR] Exception message: $($_.Exception.Message)"
                Write-ScriptLog -LogFilePath $LogFile -Message "[CONTINUE] Script will continue despite exception"
            }
        }
        
    # ====================================================================================================
    # LENOVO COMPUTER PROCESSING
    # ====================================================================================================
    # Lenovo computers use ThinkBiosConfig.hta tool for BIOS configuration
    # ====================================================================================================
    
    } elseif ($oemInfo.Manufacturer -match "Lenovo") {
        Write-ScriptLog -LogFilePath $LogFile -Message "[LENOVO] Detected Lenovo computer. Starting ThinkBiosConfig.hta and LenovoConfig.ini files download and configuration."
        
        # ========================================================================================
        # TEMPORARY PATH CREATION
        # ========================================================================================
        # Create temporary folder for Lenovo BIOS configuration tool files
        # ========================================================================================
        
        $tempPath = New-TempPath -FolderName "BitLockerTemp"
        
        # ========================================================================================
        # DOWNLOAD PATH DETERMINATION
        # ========================================================================================
        # Determine the best download source (local, remote, or URL)
        # ========================================================================================
        
        $downloadPath = Get-DownloadPath -LocalDownloadPath $LocalSharedPath `
                                        -RemoteDownloadPath $RemoteSharedPath `
                                        -DefaultDownloadPath $DefaultDownloadPath
        
        # ========================================================================================
        # LENOVO BIOS CONFIG FILES ACQUISITION
        # ========================================================================================
        # Download or sync Lenovo BIOS configuration tool files from the determined source
        # ========================================================================================
        
        if ($downloadPath.Type -eq "Local" -or $downloadPath.Type -eq "Remote") {
            # Sync files from shared network path
            $sharedPath = Join-Path -Path $downloadPath.Path -ChildPath "Lenovo"
            Write-ScriptLog -LogFilePath $LogFile -Message "[LENOVO] Syncing Lenovo BIOS config files from shared path: $sharedPath"
            
            $syncResult = Sync-SharedFiles -SharePath $sharedPath `
                                          -FileList $script:LenovoBIOSConfigFileLists `
                                          -LocalFolder $tempPath 
            
            if ($syncResult.Success -ne $true) {
                Write-ScriptLog -LogFilePath $LogFile -Message "[LENOVO ERROR] Failed to sync Lenovo BIOS config files from shared path: $sharedPath"
                return
            }
            Write-ScriptLog -LogFilePath $LogFile -Message "[LENOVO SUCCESS] Successfully synced Lenovo BIOS config files from shared path"
            
        } else {
            # Download files from URL
            Write-ScriptLog -LogFilePath $LogFile -Message "[LENOVO] Downloading Lenovo BIOS config files from URL: $LenovoBIOSConfigToolURL"
            
            foreach ($file in $script:LenovoBIOSConfigFileLists) {
                $fileUrl = ($LenovoBIOSConfigToolURL, $file) -join "/"
                $downloadResult = Get-FileFromUrl -DownloadUrl $fileUrl `
                                                  -DestinationPath $tempPath `
                                                  -FileName $file 
                
                if ($downloadResult.Success -ne $true) {
                    Write-ScriptLog -LogFilePath $LogFile -Message "[LENOVO ERROR] Failed to download Lenovo BIOS config file: $file. Error: $($downloadResult.Error)"
                    return
                }
                Write-ScriptLog -LogFilePath $LogFile -Message "[LENOVO SUCCESS] Successfully downloaded Lenovo BIOS config file: $file"
            }
        }
        
        # ========================================================================================
        # LENOVO SECUREBOOT ENABLEMENT COMMANDS
        # ========================================================================================
        # Execute Lenovo ThinkBiosConfig.hta commands to enable SecureBoot in BIOS
        # Try multiple command variations for compatibility
        # ========================================================================================
        
        $commands = @(
            "ThinkBiosConfig.hta `"config=SecureBoot,Enable`"",
            "ThinkBiosConfig.hta `"config=SecureBoot,Enabled`""
        )
        
        Write-ScriptLog -LogFilePath $LogFile -Message "[LENOVO] Executing Lenovo ThinkBiosConfig.hta commands to enable SecureBoot"
        
        foreach ($cmd in $commands) {
            try {
                Write-ScriptLog -LogFilePath $LogFile -Message "[LENOVO COMMAND] Executing: $cmd"
                
                if (-not (Invoke-ExternalCommand -WorkingDirectory $tempPath -Command $cmd)) {
                    Write-ScriptLog -LogFilePath $LogFile -Message "[LENOVO WARNING] Command failed: $cmd"
                    Write-ScriptLog -LogFilePath $LogFile -Message "[CONTINUE] Script will continue despite command failure"
                } else {
                    Write-ScriptLog -LogFilePath $LogFile -Message "[LENOVO SUCCESS] Command succeeded: $cmd"
                    
                    # ============================================================================
                    # POST-ENABLEMENT CONFIGURATION
                    # ============================================================================
                    # Execute registry configuration after successful SecureBoot enablement
                    # ============================================================================
                    
                    $registryResult = Set-SecureBootRegistryConfiguration -LogFile $LogFile
                    if ($registryResult) {
                        Write-ScriptLog -LogFilePath $LogFile -Message "[LENOVO SUCCESS] SecureBoot registry configuration updated successfully"
                        
                        # Start SecureBoot update task
                        $taskResult = Start-SecureBootUpdateTask -LogFile $LogFile
                        if ($taskResult) {
                            Write-ScriptLog -LogFilePath $LogFile -Message "[LENOVO SUCCESS] SecureBoot update task started successfully"
                            if ($NeedsRetryPostSecureBoot -and $FailedDriveLetters -and $FailedDriveLetters.Count -gt 0) {
                                try {
                                    $retryDir = Join-Path $env:ProgramData 'BitLocker'
                                    if (-not (Test-Path -Path $retryDir -PathType Container)) { New-Item -ItemType Directory -Path $retryDir | Out-Null }
                                    $retryPayload = @{ Drives = $FailedDriveLetters; Timestamp = (Get-Date).ToString('s') } | ConvertTo-Json -Depth 3
                                    Set-Content -Path (Join-Path $retryDir 'Retry.json') -Value $retryPayload -Encoding UTF8
                                    Write-ScriptLog -LogFilePath $LogFile -Message "[RETRY MARK] Saved deferred retry targets to $retryDir\Retry.json"
                                    Write-ScriptLog -LogFilePath $LogFile -Message "[EXIT] SecureBoot update initiated (Lenovo). Exiting with code 3 to defer BitLocker retry."
                                    exit 3
                                } catch {
                                    Write-ScriptLog -LogFilePath $LogFile -Message "[RETRY MARK ERROR] Failed to save retry mark: $($_.Exception.Message)"
                                }
                            }
                        } else {
                            Write-ScriptLog -LogFilePath $LogFile -Message "[LENOVO ERROR] Failed to start SecureBoot update task"
                        }
                    } else {
                        Write-ScriptLog -LogFilePath $LogFile -Message "[LENOVO ERROR] Failed to update SecureBoot registry configuration"
                    }
                }
            } catch {
                Write-ScriptLog -LogFilePath $LogFile -Message "[LENOVO ERROR] Exception during command execution: $cmd"
                Write-ScriptLog -LogFilePath $LogFile -Message "[LENOVO ERROR] Exception message: $($_.Exception.Message)"
                Write-ScriptLog -LogFilePath $LogFile -Message "[CONTINUE] Script will continue despite exception"
            }
        }
        
    # ====================================================================================================
    # HP COMPUTER PROCESSING
    # ====================================================================================================
    # HP computers require HP-specific BIOS configuration tools (to be implemented)
    # ====================================================================================================
    
    } elseif ($oemInfo.Manufacturer -match "HP") {
        Write-ScriptLog -LogFilePath $LogFile -Message "[HP] Detected HP computer. Checking HP BIOS configuration for SecureBoot enablement."
        
        # ========================================================================================
        # HP IMPLEMENTATION PLACEHOLDER
        # ========================================================================================
        # TODO: Add HP BIOS configuration tool download and installation logic
        # HP computers may use HP BIOS Configuration Utility or similar tools
        # ========================================================================================
        
        Write-ScriptLog -LogFilePath $LogFile -Message "[HP TODO] HP computer processing logic is not implemented yet."
        Write-ScriptLog -LogFilePath $LogFile -Message "[HP INFO] Manual BIOS configuration may be required for HP systems."
        
    } else {
        # ====================================================================================================
        # UNSUPPORTED OEM MANUFACTURER
        # ====================================================================================================
        # The detected OEM manufacturer is not supported by this script
        # ====================================================================================================
        
        Write-ScriptLog -LogFilePath $LogFile -Message "[UNSUPPORTED] Unsupported OEM manufacturer: $($oemInfo.Manufacturer)"
        Write-ScriptLog -LogFilePath $LogFile -Message "[EXIT] Script cannot proceed with unsupported OEM. Manual BIOS configuration required."
        exit 2 
    }
}

# ========================================================================================================
# SCRIPT EXECUTION COMPLETION
# ========================================================================================================
# Log script completion and final status
# ========================================================================================================

Write-ScriptLog -LogFilePath $LogFile -Message "=== Scheduled Task Execution Complete ==="
Write-ScriptLog -LogFilePath $LogFile -Message "=== EnableBitLocker.ps1(Version $ScriptVersion Release $ScriptReleaseDate) Script Execution Finished ==="
