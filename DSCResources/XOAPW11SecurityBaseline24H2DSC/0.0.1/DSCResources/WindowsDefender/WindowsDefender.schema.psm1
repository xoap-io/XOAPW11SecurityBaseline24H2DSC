configuration WindowsDefender
{
	Param(
        [switch]$PUAProtection = $true,
        [switch]$DisableLocalAdminMerge = $true,
        [switch]$HideExclusionsFromLocalAdmins = $true,
        [switch]$DisableRoutinelyTakingAction = $true,
        [switch]$HideExclusionsFromLocalUsers = $true,
        [switch]$PassiveRemediation = $true,
        [switch]$MpCloudBlockLevel = $true,
        [switch]$MpBafsExtendedTimeout = $true,
        [switch]$EnableConvertWarnToBlock = $true,
        [switch]$DisableIOAVProtection = $true,
        [switch]$DisableRealtimeMonitoring = $true,
        [switch]$DisableScriptScanning = $true,
        [switch]$DisableBehaviorMonitoring = $true,
        [switch]$RealtimeScanDirection = $true,
        [switch]$DisableOnAccessProtection = $true,
        [switch]$DisableScanOnRealtimeEnable = $true,
        [switch]$OobeEnableRtpAndSigUpdate = $true,
        [switch]$EnableDynamicSignatureDroppedEventReporting = $true,
        [switch]$DisableRemovableDriveScanning = $true,
        [switch]$DisablePackedExeScanning = $true,
        [switch]$QuickScanIncludeExclusions = $true,
        [switch]$SpynetReporting = $true,
        [switch]$DisableBlockAtFirstSeen = $true,
        [switch]$SubmitSamplesConsent = $true,
        [switch]$ExploitGuardASRRules = $true,
        [switch]$EnableNetworkProtection = $true
    )

    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'
	Import-DSCResource -ModuleName 'AuditPolicyDSC'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC'

    if ($PUAProtection) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\PUAProtection'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender'
            ValueType = 'Dword'
            ValueName = 'PUAProtection'
            ValueData = 1
        }
    }
    
    if ($DisableLocalAdminMerge) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\DisableLocalAdminMerge'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender'
            ValueType = 'Dword'
            ValueName = 'DisableLocalAdminMerge'
            ValueData = 0
        }
    }
    
    if ($HideExclusionsFromLocalAdmins) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\HideExclusionsFromLocalAdmins'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender'
            ValueType = 'Dword'
            ValueName = 'HideExclusionsFromLocalAdmins'
            ValueData = 1
        }
    }
    
    if ($DisableRoutinelyTakingAction) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\DisableRoutinelyTakingAction'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender'
            ValueType = 'Dword'
            ValueName = 'DisableRoutinelyTakingAction'
            ValueData = 0
        }
    }
    
    if ($HideExclusionsFromLocalUsers) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\HideExclusionsFromLocalUsers'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender'
            ValueType = 'Dword'
            ValueName = 'HideExclusionsFromLocalUsers'
            ValueData = 1
        }
    }
    if ($PassiveRemediation) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Features\PassiveRemediation'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Features'
            ValueType = 'Dword'
            ValueName = 'PassiveRemediation'
            ValueData = 1
        }
    }
    
    if ($MpCloudBlockLevel) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\MpEngine\MpCloudBlockLevel'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\MpEngine'
            ValueType = 'Dword'
            ValueName = 'MpCloudBlockLevel'
            ValueData = 2
        }
    }
    
    if ($MpBafsExtendedTimeout) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\MpEngine\MpBafsExtendedTimeout'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\MpEngine'
            ValueType = 'Dword'
            ValueName = 'MpBafsExtendedTimeout'
            ValueData = 50
        }
    }
    
    if ($EnableConvertWarnToBlock) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\NIS\EnableConvertWarnToBlock'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\NIS'
            ValueType = 'Dword'
            ValueName = 'EnableConvertWarnToBlock'
            ValueData = 1
        }
    }
    
    if ($DisableIOAVProtection) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableIOAVProtection'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection'
            ValueType = 'Dword'
            ValueName = 'DisableIOAVProtection'
            ValueData = 0
        }
    }
    
    if ($DisableRealtimeMonitoring) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection'
            ValueType = 'Dword'
            ValueName = 'DisableRealtimeMonitoring'
            ValueData = 0
        }
    }

    if ($DisableScriptScanning) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableScriptScanning'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection'
            ValueType = 'Dword'
            ValueName = 'DisableScriptScanning'
            ValueData = 0
        }
    }
    
    if ($DisableBehaviorMonitoring) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableBehaviorMonitoring'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection'
            ValueType = 'Dword'
            ValueName = 'DisableBehaviorMonitoring'
            ValueData = 0
        }
    }
    
    if ($RealtimeScanDirection) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection\RealtimeScanDirection'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection'
            ValueType = 'Dword'
            ValueName = 'RealtimeScanDirection'
            ValueData = 0
        }
    }
    
    if ($DisableOnAccessProtection) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableOnAccessProtection'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection'
            ValueType = 'Dword'
            ValueName = 'DisableOnAccessProtection'
            ValueData = 0
        }
    }
    
    if ($DisableScanOnRealtimeEnable) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableScanOnRealtimeEnable'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection'
            ValueType = 'Dword'
            ValueName = 'DisableScanOnRealtimeEnable'
            ValueData = 0
        }
    }
    
    if ($OobeEnableRtpAndSigUpdate) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection\OobeEnableRtpAndSigUpdate'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection'
            ValueType = 'Dword'
            ValueName = 'OobeEnableRtpAndSigUpdate'
            ValueData = 1
        }
    }
    
    if ($EnableDynamicSignatureDroppedEventReporting) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Reporting\EnableDynamicSignatureDroppedEventReporting'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Reporting'
            ValueType = 'Dword'
            ValueName = 'EnableDynamicSignatureDroppedEventReporting'
            ValueData = 1
        }
    }
    
    if ($DisableRemovableDriveScanning) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Scan\DisableRemovableDriveScanning'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Scan'
            ValueType = 'Dword'
            ValueName = 'DisableRemovableDriveScanning'
            ValueData = 0
        }
    }

    if ($DisablePackedExeScanning) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Scan\DisablePackedExeScanning'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Scan'
            ValueType = 'Dword'
            ValueName = 'DisablePackedExeScanning'
            ValueData = 0
        }
    }
    
    if ($QuickScanIncludeExclusions) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Scan\QuickScanIncludeExclusions'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Scan'
            ValueType = 'Dword'
            ValueName = 'QuickScanIncludeExclusions'
            ValueData = 1
        }
    }
    
    if ($SpynetReporting) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet\SpynetReporting'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet'
            ValueType = 'Dword'
            ValueName = 'SpynetReporting'
            ValueData = 2
        }
    }
    
    if ($DisableBlockAtFirstSeen) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet\DisableBlockAtFirstSeen'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet'
            ValueType = 'Dword'
            ValueName = 'DisableBlockAtFirstSeen'
            ValueData = 0
        }
    }
    
    if ($SubmitSamplesConsent) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet\SubmitSamplesConsent'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet'
            ValueType = 'Dword'
            ValueName = 'SubmitSamplesConsent'
            ValueData = 3
        }
    }
    
    if ($ExploitGuardASRRules) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\ExploitGuard_ASR_Rules'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR'
            ValueType = 'Dword'
            ValueName = 'ExploitGuard_ASR_Rules'
            ValueData = 1
        }
    }
    
    if ($EnableNetworkProtection) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection\EnableNetworkProtection'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection'
            ValueType = 'Dword'
            ValueName = 'EnableNetworkProtection'
            ValueData = 1
        }
    }

    RefreshRegistryPolicy 'ActivateClientSideExtension'
    {
        IsSingleInstance = 'Yes'
    }
}

