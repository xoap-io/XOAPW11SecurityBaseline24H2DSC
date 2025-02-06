configuration Computer
{
param(
    [bool]$AutoConnectAllowedOEM = $true,
    [bool]$EnumerateAdministrators = $true,
    [bool]$NoDriveTypeAutoRun = $true,
    [bool]$NoWebServices = $true,
    [bool]$NoAutorun = $true,
    [bool]$BackupDirectory = $true,
    [bool]$ADPasswordEncryptionEnabled = $true,
    [bool]$ADBackupDSRMPassword = $true,
    [bool]$MSAOptional = $true,
    [bool]$DisableAutomaticRestartSignOn = $true,
    [bool]$LocalAccountTokenFilterPolicy = $true,
    [bool]$EnableMPR = $true,
    [bool]$AllowEncryptionOracle = $true,
    [bool]$PKINITHashAlgorithmConfigurationEnabled = $true,
    [bool]$PKINITSHA1 = $true,
    [bool]$PKINITSHA256 = $true,
    [bool]$PKINITSHA384 = $true,
    [bool]$PKINITSHA512 = $true,
    [bool]$EnhancedAntiSpoofing = $true,
    [bool]$DisableEnclosureDownload = $true,
    [bool]$DCSettingIndex = $true,
    [bool]$ACSettingIndex = $true,
    [bool]$LetAppsActivateWithVoiceAboveLock = $true,
    [bool]$EnableMailslots = $true,
    [bool]$DisableWindowsConsumerFeatures = $true,
    [bool]$AllowProtectedCreds = $true,
    [bool]$MaxSizeEventLog = $true,
    [bool]$MaxSizeSecurityEventLog = $true,
    [bool]$MaxSizeSystemEventLog = $true,
    [bool]$NoAutoplayForNonVolume = $true,
    [bool]$DisableMotWOnInsecurePathCopy = $true,
    [bool]$AllowGameDVR = $true,
    [bool]$AlwaysInstallElevated = $true,
    [bool]$EnableUserControl = $true,
    [bool]$DeviceEnumerationPolicy = $true,
    [bool]$AuditClientDoesNotSupportEncryption = $true,
    [bool]$AuditClientDoesNotSupportSigning = $true,
    [bool]$AuditInsecureGuestLogon = $true,
    [bool]$EnableAuthRateLimiter = $true,
    [bool]$MaxSmb2Dialect = $true,
    [bool]$MinSmb2Dialect = $true,
    [bool]$InvalidAuthenticationDelayTimeInMs = $true,
    [bool]$AllowInsecureGuestAuth = $true,
    [bool]$AuditServerDoesNotSupportEncryption = $true,
    [bool]$AuditServerDoesNotSupportSigning = $true,
    [bool]$RequireEncryption = $true,
    [bool]$ShowSharedAccessUI = $true,
    [bool]$HardenedPathsSYSVOL = $true,
    [bool]$HardenedPathsNETLOGON = $true,
    [bool]$NoLockScreenCamera = $true,
    [bool]$NoLockScreenSlideshow = $true,
    [bool]$EnableScriptBlockLogging = $true,
    [bool]$EnableScriptBlockInvocationLogging = $true,  # For deletion
    [bool]$SudoEnabled = $true,
    [bool]$AllowDomainPINLogon = $true,
    [bool]$EnumerateLocalUsers = $true,
    [bool]$EnableSmartScreen = $true,
    [bool]$ShellSmartScreenLevel = $true,
    [bool]$AllowCustomSSPsAPs = $true,
    [bool]$RunAsPPL = $true,
    [bool]$fBlockNonDomain = $true,
    [bool]$AllowIndexingEncryptedStoresOrItems = $true,
    [bool]$AllowDigest = $true,
    [bool]$AllowUnencryptedTrafficClient = $true,
    [bool]$AllowBasicClient = $true,
    [bool]$AllowUnencryptedTrafficService = $true,
    [bool]$DisableRunAs = $true,
    [bool]$AllowBasic = $true,
    [bool]$NotifyMalicious = $true,
    [bool]$NotifyPasswordReuse = $true,
    [bool]$NotifyUnsafeApp = $true,
    [bool]$ServiceEnabled = $true,
    [bool]$EnableMulticast = $true,
    [bool]$EnableNetbios = $true,
    [bool]$DisableWebPnPDownload = $true,
    [bool]$RedirectionGuardPolicy = $true,
    [bool]$CopyFilesPolicy = $true,
    [bool]$RestrictDriverInstallationToAdministrators = $true,
    [bool]$RpcUseNamedPipeProtocol = $true,
    [bool]$RpcAuthentication = $true,
    [bool]$RpcProtocols = $true,
    [bool]$ForceKerberosForRpc = $true,
    [bool]$RpcTcpPort = $true,
    [bool]$RestrictRemoteClients = $true,
    [bool]$fUseMailto = $true,  # For deletion
    [bool]$fAllowToGetHelp = $true,
    [bool]$fAllowFullControl = $true,  # For deletion
    [bool]$MaxTicketExpiry = $true,  # For deletion
    [bool]$MaxTicketExpiryUnits = $true,  # For deletion
    [bool]$MinEncryptionLevel = $true,
    [bool]$fPromptForPassword = $true,
    [bool]$fDisableCdm = $true,
    [bool]$DisablePasswordSaving = $true,
    [bool]$fEncryptRPCTraffic = $true,
    [bool]$PolicyVersion = $true,
    [bool]$DefaultOutboundAction = $true,
    [bool]$DisableNotifications = $true,
    [bool]$EnableFirewall = $true,
    [bool]$DefaultInboundAction = $true,
    [bool]$LogDroppedPackets = $true,
    [bool]$LogFileSize = $true,
    [bool]$LogSuccessfulConnections = $true,
    [bool]$EnableFirewallPrivateProfile = $true,
    [bool]$DisableNotificationsPrivateProfile = $true,
    [bool]$DefaultInboundActionPrivate = $true,
    [bool]$DefaultOutboundActionPrivate = $true,
    [bool]$LogSuccessfulConnectionsPrivate = $true,
    [bool]$LogDroppedPacketsPrivate = $true,
    [bool]$LogFileSizePrivate = $true,
    [bool]$DefaultOutboundActionPublic = $true,
    [bool]$EnableFirewallPublicProfile = $true,
    [bool]$DisableNotificationsPublicProfile = $true,
    [bool]$AllowLocalIPsecPolicyMerge = $true,
    [bool]$AllowLocalPolicyMerge = $true,
    [bool]$DefaultInboundActionPublicProfile = $true,
    [bool]$LogFileSizePublicProfile = $true,
    [bool]$LogDroppedPacketsPublicProfile = $true,
    [bool]$LogSuccessfulConnectionsPublicProfile = $true,
    [bool]$AllowWindowsInkWorkspace = $true,
    [bool]$RpcAuthnLevelPrivacyEnabled = $true,
    [bool]$UseLogonCredential = $true,
    [bool]$DisableExceptionChainValidation = $true,
    [bool]$DriverLoadPolicy = $true,
    [bool]$SMB1 = $true,
    [bool]$StartMRxSmb10 = $true,
    [bool]$NoNameReleaseOnDemand = $true,
    [bool]$NodeType = $true,
    [bool]$EnableICMPRedirect = $true,
    [bool]$DisableIPSourceRoutingTcpip = $true,
    [bool]$DisableIPSourceRoutingTcpip6 = $true,
    [bool]$AuditCredentialValidationSuccess = $true,
    [bool]$AuditCredentialValidationFailure = $true,
    [bool]$AuditSecurityGroupManagementSuccess = $true,
    [bool]$AuditSecurityGroupManagementFailure = $true,
    [bool]$AuditUserAccountManagementSuccess = $true,
    [bool]$AuditUserAccountManagementFailure = $true,
    [bool]$AuditPnpActivitySuccess = $true,
    [bool]$AuditPnpActivityFailure = $true,
    [bool]$AuditProcessCreationSuccess = $true,
    [bool]$AuditProcessCreationFailure = $true,
    [bool]$AuditAccountLockoutFailure = $true,
    [bool]$AuditAccountLockoutSuccess = $true,
    [bool]$AuditGroupMembershipSuccess = $true,
    [bool]$AuditGroupMembershipFailure = $true,
    [bool]$AuditLogonSuccess = $true,
    [bool]$AuditLogonFailure = $true,
    [bool]$AuditOtherLogonLogoffEventsSuccess = $true,
    [bool]$AuditOtherLogonLogoffEventsFailure = $true,
    [bool]$AuditSpecialLogonSuccess = $true,
    [bool]$AuditSpecialLogonFailure = $true,
    [bool]$AuditDetailedFileShareFailure = $true,
    [bool]$AuditDetailedFileShareSuccess = $true,
    [bool]$AuditFileShareSuccess = $true,
    [bool]$AuditFileShareFailure = $true,
    [bool]$AuditOtherObjectAccessEventsSuccess = $true,
    [bool]$AuditOtherObjectAccessEventsFailure = $true,
    [bool]$AuditRemovableStorageSuccess = $true,
    [bool]$AuditRemovableStorageFailure = $true,
    [bool]$AuditPolicyChangeSuccess = $true,
    [bool]$AuditPolicyChangeFailure = $true,
    [bool]$AuditAuthenticationPolicyChangeSuccess = $true,
    [bool]$AuditAuthenticationPolicyChangeFailure = $true,
    [bool]$AuditMpssvcRuleLevelPolicyChangeSuccess = $true,
    [bool]$AuditMpssvcRuleLevelPolicyChangeFailure = $true,
    [bool]$AuditOtherPolicyChangeEventsFailure = $true,
    [bool]$AuditOtherPolicyChangeEventsSuccess = $true,
    [bool]$AuditSensitivePrivilegeUseSuccess = $true,
    [bool]$AuditSensitivePrivilegeUseFailure = $true,
    [bool]$AuditOtherSystemEventsSuccess = $true,
    [bool]$AuditOtherSystemEventsFailure = $true,
    [bool]$AuditSecurityStateChangeSuccess = $true,
    [bool]$AuditSecurityStateChangeFailure = $true,
    [bool]$AuditSecuritySystemExtensionSuccess = $true,
    [bool]$AuditSecuritySystemExtensionFailure = $true,
    [bool]$AuditSystemIntegritySuccess = $true,
    [bool]$AuditSystemIntegrityFailure = $true,
    [bool]$LSAAnonymousNameLookup = $true,
    [bool]$CreateGlobalObjects = $true,
    [bool]$ActAsPartOfTheOperatingSystem = $true,
    [bool]$DenyAccessToThisComputerFromTheNetwork = $true,
    [bool]$DenyLogOnThroughRemoteDesktopServices = $true,
    [bool]$PerformVolumeMaintenanceTasks = $true,
    [bool]$AccessCredentialManagerAsTrustedCaller = $true,
    [bool]$CreateTokenObject = $true,
    [bool]$LockPagesInMemory = $true,
    [bool]$CreatePagefile = $true,
    [bool]$DebugPrograms = $true,
    [bool]$RestoreFilesAndDirectories = $true,
    [bool]$TakeOwnershipOfFilesOrOtherObjects = $true,
    [bool]$AccessThisComputerFromTheNetwork = $true,
    [bool]$EnableTrustedForDelegation = $true,
    [bool]$AllowLogOnLocally = $true,
    [bool]$ModifyFirmwareEnvironmentValues = $true,
    [bool]$BackUpFilesAndDirectories = $true,
    [bool]$ManageAuditingAndSecurityLog = $true,
    [bool]$ProfileSingleProcess = $true,
    [bool]$LoadAndUnloadDeviceDrivers = $true,
    [bool]$ForceShutdownFromRemoteSystem = $true,
    [bool]$CreatePermanentSharedObjects = $true,
    [bool]$ImpersonateClientAfterAuthentication = $true,
    [bool]$DomainMemberRequireStrongSessionKey = $true,
    [bool]$AuditForceAuditPolicy = $true,
    [bool]$NetworkAccessDoNotAllowAnonymousEnumeration = $true,
    [bool]$UACOnlyElevateUIAccessAppInSecureLocations = $true,
    [bool]$UACBehaviorOfElevationPromptForStandardUsers = $true,
    [bool]$InteractiveLogonSmartCardRemovalBehavior = $true,
    [bool]$DomainMemberEncryptOrSignSecureChannelData = $true,
    [bool]$DomainMemberDisableMachineAccountPasswordChanges = $true,
    [bool]$UACBehaviorOfElevationPromptForAdministrators = $true,
    [bool]$UACAdminApprovalModeForBuiltInAdministrator = $true,
    [bool]$DomainMemberDigitallySignSecureChannelData = $true,
    [bool]$NetworkSecurityLDAPClientSigningRequirements = $true,
    [bool]$SendUnencryptedPasswordToThirdPartySMBServers = $true,
    [bool]$DoNotStoreLANManagerHashOnNextPasswordChange = $true,
    [bool]$MinimumSessionSecurityForNTLM = $true,
    [bool]$MachineInactivityLimit = $true,
    [bool]$RestrictClientsAllowedToMakeRemoteCallsToSAM = $true,
    [bool]$DigitallyEncryptSecureChannelData = $true,
    [bool]$DetectApplicationInstallationsPromptForElevation = $true,
    [bool]$RestrictAnonymousAccessToNamedPipesAndShares = $true,
    [bool]$DigitallySignCommunicationsAlways = $true,
    [bool]$NetworkSecurityLANManagerAuthenticationLevel = $true,
    [bool]$AccountsLimitLocalAccountUseOfBlankPasswords = $true,
    [bool]$MicrosoftNetworkServerDigitallySignCommunications = $true,
    [bool]$NetworkSecurityMinimumSessionSecurityForNTLM = $true,
    [bool]$StrengthenDefaultPermissionsOfInternalSystemObjects = $true,
    [bool]$NetworkSecurityAllowLocalSystemNullSessionFallback = $true,
    [bool]$UACRunAllAdministratorsInAdminApprovalMode = $true,
    [bool]$UACVirtualizeFileAndRegistryWriteFailures = $true
)

	Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'
	Import-DSCResource -ModuleName 'AuditPolicyDSC'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC'

    if ($AutoConnectAllowedOEM) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\WcmSvc\wifinetworkmanager\config\AutoConnectAllowedOEM'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Microsoft\WcmSvc\wifinetworkmanager\config'
            ValueType = 'Dword'
            ValueName = 'AutoConnectAllowedOEM'
            ValueData = 0
        }
    }
    
    if ($EnumerateAdministrators) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI\EnumerateAdministrators'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI'
            ValueType = 'Dword'
            ValueName = 'EnumerateAdministrators'
            ValueData = 0
        }
    }
    
    if ($NoDriveTypeAutoRun) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueType = 'Dword'
            ValueName = 'NoDriveTypeAutoRun'
            ValueData = 255
        }
    }
    
    if ($NoWebServices) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoWebServices'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueType = 'Dword'
            ValueName = 'NoWebServices'
            ValueData = 1
        }
    }

    if ($NoAutorun) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoAutorun'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueType = 'Dword'
            ValueName = 'NoAutorun'
            ValueData = 1
        }
    }
    
    if ($BackupDirectory) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS\BackupDirectory'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS'
            ValueType = 'Dword'
            ValueName = 'BackupDirectory'
            ValueData = 2
        }
    }
    
    if ($ADPasswordEncryptionEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS\ADPasswordEncryptionEnabled'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS'
            ValueType = 'Dword'
            ValueName = 'ADPasswordEncryptionEnabled'
            ValueData = 1
        }
    }
    
    if ($ADBackupDSRMPassword) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS\ADBackupDSRMPassword'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS'
            ValueType = 'Dword'
            ValueName = 'ADBackupDSRMPassword'
            ValueData = 1
        }
    }

    if ($MSAOptional) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\MSAOptional'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueType = 'Dword'
            ValueName = 'MSAOptional'
            ValueData = 1
        }
    }
    
    if ($DisableAutomaticRestartSignOn) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableAutomaticRestartSignOn'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueType = 'Dword'
            ValueName = 'DisableAutomaticRestartSignOn'
            ValueData = 1
        }
    }
    
    if ($LocalAccountTokenFilterPolicy) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueType = 'Dword'
            ValueName = 'LocalAccountTokenFilterPolicy'
            ValueData = 0
        }
    }
    
    if ($EnableMPR) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableMPR'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueType = 'Dword'
            ValueName = 'EnableMPR'
            ValueData = 0
        }
    }

    if ($AllowEncryptionOracle) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters\AllowEncryptionOracle'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters'
            ValueType = 'Dword'
            ValueName = 'AllowEncryptionOracle'
            ValueData = 0
        }
    }
    
    if ($PKINITHashAlgorithmConfigurationEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters\PKINITHashAlgorithmConfigurationEnabled'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters'
            ValueType = 'Dword'
            ValueName = 'PKINITHashAlgorithmConfigurationEnabled'
            ValueData = 1
        }
    }
    
    if ($PKINITSHA1) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters\PKINITSHA1'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters'
            ValueType = 'Dword'
            ValueName = 'PKINITSHA1'
            ValueData = 0
        }
    }
    
    if ($PKINITSHA256) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters\PKINITSHA256'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters'
            ValueType = 'Dword'
            ValueName = 'PKINITSHA256'
            ValueData = 3
        }
    }
    
    if ($PKINITSHA384) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters\PKINITSHA384'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters'
            ValueType = 'Dword'
            ValueName = 'PKINITSHA384'
            ValueData = 3
        }
    }

    if ($PKINITSHA512) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters\PKINITSHA512'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters'
            ValueType = 'Dword'
            ValueName = 'PKINITSHA512'
            ValueData = 3
        }
    }

    if ($EnhancedAntiSpoofing) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Biometrics\FacialFeatures\EnhancedAntiSpoofing'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Biometrics\FacialFeatures'
            ValueType = 'Dword'
            ValueName = 'EnhancedAntiSpoofing'
            ValueData = 1
        }
    }
    
    if ($DisableEnclosureDownload) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Feeds\DisableEnclosureDownload'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Feeds'
            ValueType = 'Dword'
            ValueName = 'DisableEnclosureDownload'
            ValueData = 1
        }
    }
    
    if ($DCSettingIndex) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\DCSettingIndex'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
            ValueType = 'Dword'
            ValueName = 'DCSettingIndex'
            ValueData = 1
        }
    }
    
    if ($ACSettingIndex) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\ACSettingIndex'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
            ValueType = 'Dword'
            ValueName = 'ACSettingIndex'
            ValueData = 1
        }
    }
    
    if ($LetAppsActivateWithVoiceAboveLock) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy\LetAppsActivateWithVoiceAboveLock'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy'
            ValueType = 'Dword'
            ValueName = 'LetAppsActivateWithVoiceAboveLock'
            ValueData = 2
        }
    }
    
    if ($EnableMailslots) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Bowser\EnableMailslots'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\Bowser'
            ValueType = 'Dword'
            ValueName = 'EnableMailslots'
            ValueData = 0
        }
    }
    
    if ($DisableWindowsConsumerFeatures) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CloudContent\DisableWindowsConsumerFeatures'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CloudContent'
            ValueType = 'Dword'
            ValueName = 'DisableWindowsConsumerFeatures'
            ValueData = 1
        }
    }
    
    if ($AllowProtectedCreds) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowProtectedCreds'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation'
            ValueType = 'Dword'
            ValueName = 'AllowProtectedCreds'
            ValueData = 1
        }
    }
    
    if ($MaxSizeEventLog) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application\MaxSize'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application'
            ValueType = 'Dword'
            ValueName = 'MaxSize'
            ValueData = 32768
        }
    }

    if ($MaxSizeSecurityEventLog) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security\MaxSize'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security'
            ValueType = 'Dword'
            ValueName = 'MaxSize'
            ValueData = 196608
        }
    }
    
    if ($MaxSizeSystemEventLog) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\System\MaxSize'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\System'
            ValueType = 'Dword'
            ValueName = 'MaxSize'
            ValueData = 32768
        }
    }
    
    if ($NoAutoplayForNonVolume) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Explorer\NoAutoplayfornonVolume'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\Explorer'
            ValueType = 'Dword'
            ValueName = 'NoAutoplayfornonVolume'
            ValueData = 1
        }
    }
    
    if ($DisableMotWOnInsecurePathCopy) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Explorer\DisableMotWOnInsecurePathCopy'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\Explorer'
            ValueType = 'Dword'
            ValueName = 'DisableMotWOnInsecurePathCopy'
            ValueData = 0
        }
    }
    
    if ($AllowGameDVR) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\GameDVR\AllowGameDVR'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\GameDVR'
            ValueType = 'Dword'
            ValueName = 'AllowGameDVR'
            ValueData = 0
        }
    }

    if ($AlwaysInstallElevated) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\Installer'
            ValueType = 'Dword'
            ValueName = 'AlwaysInstallElevated'
            ValueData = 0
        }
    }
    
    if ($EnableUserControl) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Installer\EnableUserControl'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\Installer'
            ValueType = 'Dword'
            ValueName = 'EnableUserControl'
            ValueData = 0
        }
    }
    
    if ($DeviceEnumerationPolicy) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Kernel DMA Protection\DeviceEnumerationPolicy'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\Kernel DMA Protection'
            ValueType = 'Dword'
            ValueName = 'DeviceEnumerationPolicy'
            ValueData = 0
        }
    }
    
    if ($AuditClientDoesNotSupportEncryption) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\LanmanServer\AuditClientDoesNotSupportEncryption'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\LanmanServer'
            ValueType = 'Dword'
            ValueName = 'AuditClientDoesNotSupportEncryption'
            ValueData = 1
        }
    }
    
    if ($AuditClientDoesNotSupportSigning) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\LanmanServer\AuditClientDoesNotSupportSigning'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\LanmanServer'
            ValueType = 'Dword'
            ValueName = 'AuditClientDoesNotSupportSigning'
            ValueData = 1
        }
    }
    
    if ($AuditInsecureGuestLogon) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\LanmanServer\AuditInsecureGuestLogon'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\LanmanServer'
            ValueType = 'Dword'
            ValueName = 'AuditInsecureGuestLogon'
            ValueData = 1
        }
    }
    
    if ($EnableAuthRateLimiter) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\LanmanServer\EnableAuthRateLimiter'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\LanmanServer'
            ValueType = 'Dword'
            ValueName = 'EnableAuthRateLimiter'
            ValueData = 1
        }
    }
    
    if ($MaxSmb2Dialect) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\LanmanServer\MaxSmb2Dialect'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\LanmanServer'
            ValueType = 'Dword'
            ValueName = 'MaxSmb2Dialect'
            ValueData = 785
        }
    }
    
    if ($MinSmb2Dialect) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\LanmanServer\MinSmb2Dialect'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\LanmanServer'
            ValueType = 'Dword'
            ValueName = 'MinSmb2Dialect'
            ValueData = 768
        }
    }

    if ($InvalidAuthenticationDelayTimeInMs) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\LanmanServer\InvalidAuthenticationDelayTimeInMs'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\LanmanServer'
            ValueType = 'Dword'
            ValueName = 'InvalidAuthenticationDelayTimeInMs'
            ValueData = 2000
        }
    }
    
    if ($AllowInsecureGuestAuth) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation\AllowInsecureGuestAuth'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation'
            ValueType = 'Dword'
            ValueName = 'AllowInsecureGuestAuth'
            ValueData = 0
        }
    }
    
    if ($AuditInsecureGuestLogon) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation\AuditInsecureGuestLogon'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation'
            ValueType = 'Dword'
            ValueName = 'AuditInsecureGuestLogon'
            ValueData = 1
        }
    }
    
    if ($AuditServerDoesNotSupportEncryption) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation\AuditServerDoesNotSupportEncryption'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation'
            ValueType = 'Dword'
            ValueName = 'AuditServerDoesNotSupportEncryption'
            ValueData = 1
        }
    }
    
    if ($AuditServerDoesNotSupportSigning) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation\AuditServerDoesNotSupportSigning'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation'
            ValueType = 'Dword'
            ValueName = 'AuditServerDoesNotSupportSigning'
            ValueData = 1
        }
    }
    
    if ($MaxSmb2Dialect) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation\MaxSmb2Dialect'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation'
            ValueType = 'Dword'
            ValueName = 'MaxSmb2Dialect'
            ValueData = 785
        }
    }
    
    if ($MinSmb2Dialect) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation\MinSmb2Dialect'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation'
            ValueType = 'Dword'
            ValueName = 'MinSmb2Dialect'
            ValueData = 768
        }
    }
    
    if ($RequireEncryption) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation\RequireEncryption'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation'
            ValueType = 'Dword'
            ValueName = 'RequireEncryption'
            ValueData = 0
        }
    }
    if ($ShowSharedAccessUI) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Network Connections\NC_ShowSharedAccessUI'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\Network Connections'
            ValueType = 'Dword'
            ValueName = 'NC_ShowSharedAccessUI'
            ValueData = 0
        }
    }
    
    if ($EnableMailslots) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\EnableMailslots'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider'
            ValueType = 'Dword'
            ValueName = 'EnableMailslots'
            ValueData = 0
        }
    }
    
    if ($HardenedPathsSYSVOL) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\*\SYSVOL'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
            ValueType = 'String'
            ValueName = '\\*\SYSVOL'
            ValueData = 'RequireMutualAuthentication=1,RequireIntegrity=1'
        }
    }
    
    if ($HardenedPathsNETLOGON) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\*\NETLOGON'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
            ValueType = 'String'
            ValueName = '\\*\NETLOGON'
            ValueData = 'RequireMutualAuthentication=1,RequireIntegrity=1'
        }
    }
    
    if ($NoLockScreenCamera) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Personalization\NoLockScreenCamera'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\Personalization'
            ValueType = 'Dword'
            ValueName = 'NoLockScreenCamera'
            ValueData = 1
        }
    }

    if ($NoLockScreenSlideshow) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Personalization\NoLockScreenSlideshow'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\Personalization'
            ValueType = 'Dword'
            ValueName = 'NoLockScreenSlideshow'
            ValueData = 1
        }
    }
    
    if ($EnableScriptBlockLogging) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
            ValueType = 'Dword'
            ValueName = 'EnableScriptBlockLogging'
            ValueData = 1
        }
    }
    
    if ($EnableScriptBlockInvocationLogging) {
        RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockInvocationLogging'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
            Ensure = 'Absent'  # This means it's being deleted
            ValueType = 'String'
            ValueName = 'EnableScriptBlockInvocationLogging'
            ValueData = ''
        }
    }
    
    if ($SudoEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Sudo\Enabled'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\Sudo'
            ValueType = 'Dword'
            ValueName = 'Enabled'
            ValueData = 0
        }
    }

    if ($AllowDomainPINLogon) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\AllowDomainPINLogon'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\System'
            ValueType = 'Dword'
            ValueName = 'AllowDomainPINLogon'
            ValueData = 0
        }
    }
    
    if ($EnumerateLocalUsers) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\EnumerateLocalUsers'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\System'
            ValueType = 'Dword'
            ValueName = 'EnumerateLocalUsers'
            ValueData = 0
        }
    }
    
    if ($EnableSmartScreen) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\EnableSmartScreen'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\System'
            ValueType = 'Dword'
            ValueName = 'EnableSmartScreen'
            ValueData = 1
        }
    }
    
    if ($ShellSmartScreenLevel) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\ShellSmartScreenLevel'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\System'
            ValueType = 'String'
            ValueName = 'ShellSmartScreenLevel'
            ValueData = 'Block'
        }
    }
    
    if ($AllowCustomSSPsAPs) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\AllowCustomSSPsAPs'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\System'
            ValueType = 'Dword'
            ValueName = 'AllowCustomSSPsAPs'
            ValueData = 0
        }
    }
    if ($RunAsPPL) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\RunAsPPL'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\System'
            ValueType = 'Dword'
            ValueName = 'RunAsPPL'
            ValueData = 1
        }
    }
    
    if ($fBlockNonDomain) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\fBlockNonDomain'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy'
            ValueType = 'Dword'
            ValueName = 'fBlockNonDomain'
            ValueData = 1
        }
    }
    
    if ($AllowIndexingEncryptedStoresOrItems) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Windows Search\AllowIndexingEncryptedStoresOrItems'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\Windows Search'
            ValueType = 'Dword'
            ValueName = 'AllowIndexingEncryptedStoresOrItems'
            ValueData = 0
        }
    }
    
    if ($AllowDigest) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\AllowDigest'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client'
            ValueType = 'Dword'
            ValueName = 'AllowDigest'
            ValueData = 0
        }
    }
    
    if ($AllowUnencryptedTrafficClient) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\AllowUnencryptedTraffic'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client'
            ValueType = 'Dword'
            ValueName = 'AllowUnencryptedTraffic'
            ValueData = 0
        }
    }
    
    if ($AllowBasicClient) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\AllowBasic'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client'
            ValueType = 'Dword'
            ValueName = 'AllowBasic'
            ValueData = 0
        }
    }
    
    if ($AllowUnencryptedTrafficService) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\AllowUnencryptedTraffic'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service'
            ValueType = 'Dword'
            ValueName = 'AllowUnencryptedTraffic'
            ValueData = 0
        }
    }

    if ($DisableRunAs) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\DisableRunAs'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service'
            ValueType = 'Dword'
            ValueName = 'DisableRunAs'
            ValueData = 1
        }
    }
    
    if ($AllowBasic) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\AllowBasic'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service'
            ValueType = 'Dword'
            ValueName = 'AllowBasic'
            ValueData = 0
        }
    }
    
    if ($NotifyMalicious) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WTDS\Components\NotifyMalicious'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\WTDS\Components'
            ValueType = 'Dword'
            ValueName = 'NotifyMalicious'
            ValueData = 1
        }
    }
    
    if ($NotifyPasswordReuse) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WTDS\Components\NotifyPasswordReuse'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\WTDS\Components'
            ValueType = 'Dword'
            ValueName = 'NotifyPasswordReuse'
            ValueData = 1
        }
    }
    
    if ($NotifyUnsafeApp) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WTDS\Components\NotifyUnsafeApp'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\WTDS\Components'
            ValueType = 'Dword'
            ValueName = 'NotifyUnsafeApp'
            ValueData = 1
        }
    }
    
    if ($ServiceEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WTDS\Components\ServiceEnabled'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\WTDS\Components'
            ValueType = 'Dword'
            ValueName = 'ServiceEnabled'
            ValueData = 1
        }
    }
    
    if ($EnableMulticast) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient'
            ValueType = 'Dword'
            ValueName = 'EnableMulticast'
            ValueData = 0
        }
    }
    if ($EnableNetbios) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient\EnableNetbios'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient'
            ValueType = 'Dword'
            ValueName = 'EnableNetbios'
            ValueData = 2
        }
    }
    
    if ($DisableWebPnPDownload) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Printers\DisableWebPnPDownload'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers'
            ValueType = 'Dword'
            ValueName = 'DisableWebPnPDownload'
            ValueData = 1
        }
    }
    
    if ($RedirectionGuardPolicy) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RedirectionGuardPolicy'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers'
            ValueType = 'Dword'
            ValueName = 'RedirectionGuardPolicy'
            ValueData = 1
        }
    }
    
    if ($CopyFilesPolicy) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Printers\CopyFilesPolicy'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers'
            ValueType = 'Dword'
            ValueName = 'CopyFilesPolicy'
            ValueData = 1
        }
    }
    
    if ($RestrictDriverInstallationToAdministrators) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint\RestrictDriverInstallationToAdministrators'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
            ValueType = 'Dword'
            ValueName = 'RestrictDriverInstallationToAdministrators'
            ValueData = 1
        }
    }
    
    if ($RpcUseNamedPipeProtocol) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RPC\RpcUseNamedPipeProtocol'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RPC'
            ValueType = 'Dword'
            ValueName = 'RpcUseNamedPipeProtocol'
            ValueData = 0
        }
    }
    
    if ($RpcAuthentication) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RPC\RpcAuthentication'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RPC'
            ValueType = 'Dword'
            ValueName = 'RpcAuthentication'
            ValueData = 0
        }
    }
    
    if ($RpcProtocols) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RPC\RpcProtocols'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RPC'
            ValueType = 'Dword'
            ValueName = 'RpcProtocols'
            ValueData = 5
        }
    }
    if ($ForceKerberosForRpc) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RPC\ForceKerberosForRpc'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RPC'
            ValueType = 'Dword'
            ValueName = 'ForceKerberosForRpc'
            ValueData = 0
        }
    }
    
    if ($RpcTcpPort) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RPC\RpcTcpPort'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RPC'
            ValueType = 'Dword'
            ValueName = 'RpcTcpPort'
            ValueData = 0
        }
    }
    
    if ($RestrictRemoteClients) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Rpc\RestrictRemoteClients'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Rpc'
            ValueType = 'Dword'
            ValueName = 'RestrictRemoteClients'
            ValueData = 1
        }
    }
    
    if ($fUseMailto) {
        RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows NT\Terminal Services\fUseMailto'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
            Ensure = 'Absent'  # This means it's being deleted
            ValueType = 'String'
            ValueName = 'fUseMailto'
            ValueData = ''
        }
    }
    
    if ($fAllowToGetHelp) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\fAllowToGetHelp'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'Dword'
            ValueName = 'fAllowToGetHelp'
            ValueData = 0
        }
    }
    
    if ($fAllowFullControl) {
        RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows NT\Terminal Services\fAllowFullControl'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
            Ensure = 'Absent'  # This means it's being deleted
            ValueType = 'String'
            ValueName = 'fAllowFullControl'
            ValueData = ''
        }
    }
    
    if ($MaxTicketExpiry) {
        RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows NT\Terminal Services\MaxTicketExpiry'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
            Ensure = 'Absent'  # This means it's being deleted
            ValueType = 'String'
            ValueName = 'MaxTicketExpiry'
            ValueData = ''
        }
    }

    if ($MaxTicketExpiryUnits) {
        RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows NT\Terminal Services\MaxTicketExpiryUnits'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
            Ensure = 'Absent'  # This means it's being deleted
            ValueType = 'String'
            ValueName = 'MaxTicketExpiryUnits'
            ValueData = ''
        }
    }
    
    if ($MinEncryptionLevel) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\MinEncryptionLevel'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'Dword'
            ValueName = 'MinEncryptionLevel'
            ValueData = 3
        }
    }
    
    if ($fPromptForPassword) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\fPromptForPassword'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'Dword'
            ValueName = 'fPromptForPassword'
            ValueData = 1
        }
    }
    
    if ($fDisableCdm) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\fDisableCdm'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'Dword'
            ValueName = 'fDisableCdm'
            ValueData = 1
        }
    }
    
    if ($DisablePasswordSaving) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\DisablePasswordSaving'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'Dword'
            ValueName = 'DisablePasswordSaving'
            ValueData = 1
        }
    }
    
    if ($fEncryptRPCTraffic) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\fEncryptRPCTraffic'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'Dword'
            ValueName = 'fEncryptRPCTraffic'
            ValueData = 1
        }
    }
    
    if ($PolicyVersion) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\PolicyVersion'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall'
            ValueType = 'Dword'
            ValueName = 'PolicyVersion'
            ValueData = 538
        }
    }
    
    if ($DefaultOutboundAction) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\DefaultOutboundAction'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
            ValueType = 'Dword'
            ValueName = 'DefaultOutboundAction'
            ValueData = 0
        }
    }
    
    if ($DisableNotifications) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\DisableNotifications'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
            ValueType = 'Dword'
            ValueName = 'DisableNotifications'
            ValueData = 1
        }
    }
    
    if ($EnableFirewall) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\EnableFirewall'
         {
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
              ValueType = 'Dword'
              ValueName = 'EnableFirewall'
              ValueData = 1
         }
    }

    if ($DefaultInboundAction) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\DefaultInboundAction'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
            ValueType = 'Dword'
            ValueName = 'DefaultInboundAction'
            ValueData = 1
        }
    }
    
    if ($LogDroppedPackets) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogDroppedPackets'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
            ValueType = 'Dword'
            ValueName = 'LogDroppedPackets'
            ValueData = 1
        }
    }
    
    if ($LogFileSize) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogFileSize'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
            ValueType = 'Dword'
            ValueName = 'LogFileSize'
            ValueData = 16384
        }
    }
    
    if ($LogSuccessfulConnections) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogSuccessfulConnections'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
            ValueType = 'Dword'
            ValueName = 'LogSuccessfulConnections'
            ValueData = 1
        }
    }
    
    if ($EnableFirewallPrivateProfile) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\EnableFirewall'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueType = 'Dword'
            ValueName = 'EnableFirewall'
            ValueData = 1
        }
    }
    
    if ($DisableNotificationsPrivateProfile) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\DisableNotifications'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueType = 'Dword'
            ValueName = 'DisableNotifications'
            ValueData = 1
        }
    }
    if ($DefaultInboundActionPrivate) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\DefaultInboundAction'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueType = 'Dword'
            ValueName = 'DefaultInboundAction'
            ValueData = 1
        }
    }
    
    if ($DefaultOutboundActionPrivate) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\DefaultOutboundAction'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueType = 'Dword'
            ValueName = 'DefaultOutboundAction'
            ValueData = 0
        }
    }
    
    if ($LogSuccessfulConnectionsPrivate) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\LogSuccessfulConnections'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
            ValueType = 'Dword'
            ValueName = 'LogSuccessfulConnections'
            ValueData = 1
        }
    }
    
    if ($LogDroppedPacketsPrivate) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\LogDroppedPackets'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
            ValueType = 'Dword'
            ValueName = 'LogDroppedPackets'
            ValueData = 1
        }
    }
    
    if ($LogFileSizePrivate) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\LogFileSize'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
            ValueType = 'Dword'
            ValueName = 'LogFileSize'
            ValueData = 16384
        }
    }
    
    if ($DefaultOutboundActionPublic) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\DefaultOutboundAction'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueType = 'Dword'
            ValueName = 'DefaultOutboundAction'
            ValueData = 0
        }
    }

    if ($EnableFirewallPublicProfile) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\EnableFirewall'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueType = 'Dword'
            ValueName = 'EnableFirewall'
            ValueData = 1
        }
    }
    
    if ($DisableNotificationsPublicProfile) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\DisableNotifications'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueType = 'Dword'
            ValueName = 'DisableNotifications'
            ValueData = 1
        }
    }
    
    if ($AllowLocalIPsecPolicyMerge) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\AllowLocalIPsecPolicyMerge'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueType = 'Dword'
            ValueName = 'AllowLocalIPsecPolicyMerge'
            ValueData = 0
        }
    }
    
    if ($AllowLocalPolicyMerge) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\AllowLocalPolicyMerge'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueType = 'Dword'
            ValueName = 'AllowLocalPolicyMerge'
            ValueData = 0
        }
    }
    
    if ($DefaultInboundActionPublicProfile) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\DefaultInboundAction'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueType = 'Dword'
            ValueName = 'DefaultInboundAction'
            ValueData = 1
        }
    }
    
    if ($LogFileSizePublicProfile) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogFileSize'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
            ValueType = 'Dword'
            ValueName = 'LogFileSize'
            ValueData = 16384
        }
    }
    
    if ($LogDroppedPacketsPublicProfile) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogDroppedPackets'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
            ValueType = 'Dword'
            ValueName = 'LogDroppedPackets'
            ValueData = 1
        }
    }
    
    if ($LogSuccessfulConnectionsPublicProfile) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogSuccessfulConnections'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
            ValueType = 'Dword'
            ValueName = 'LogSuccessfulConnections'
            ValueData = 1
        }
    }

    if ($AllowWindowsInkWorkspace) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsInkWorkspace\AllowWindowsInkWorkspace'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\WindowsInkWorkspace'
            ValueType = 'Dword'
            ValueName = 'AllowWindowsInkWorkspace'
            ValueData = 1
        }
    }
    
    if ($RunAsPPL) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
            ValueType = 'Dword'
            ValueName = 'RunAsPPL'
            ValueData = 1
        }
    }
    
    if ($RpcAuthnLevelPrivacyEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Control\Print\RpcAuthnLevelPrivacyEnabled'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Print'
            ValueType = 'Dword'
            ValueName = 'RpcAuthnLevelPrivacyEnabled'
            ValueData = 1
        }
    }
    
    if ($UseLogonCredential) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
            ValueType = 'Dword'
            ValueName = 'UseLogonCredential'
            ValueData = 0
        }
    }
    
    if ($DisableExceptionChainValidation) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel\DisableExceptionChainValidation'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel'
            ValueType = 'Dword'
            ValueName = 'DisableExceptionChainValidation'
            ValueData = 0
        }
    }
    
    if ($DriverLoadPolicy) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\DriverLoadPolicy'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch'
            ValueType = 'Dword'
            ValueName = 'DriverLoadPolicy'
            ValueData = 3
        }
    }
    
    if ($SMB1) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
            ValueType = 'Dword'
            ValueName = 'SMB1'
            ValueData = 0
        }
    }
    
    if ($StartMRxSmb10) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\MrxSmb10\Start'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\MrxSmb10'
            ValueType = 'Dword'
            ValueName = 'Start'
            ValueData = 4
        }
    }
    
    if ($NoNameReleaseOnDemand) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters\NoNameReleaseOnDemand'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters'
            ValueType = 'Dword'
            ValueName = 'NoNameReleaseOnDemand'
            ValueData = 1
        }
    }

    if ($NodeType) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters\NodeType'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters'
            ValueType = 'Dword'
            ValueName = 'NodeType'
            ValueData = 2
        }
    }
    
    if ($EnableICMPRedirect) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\EnableICMPRedirect'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
            ValueType = 'Dword'
            ValueName = 'EnableICMPRedirect'
            ValueData = 0
        }
    }
    
    if ($DisableIPSourceRoutingTcpip) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\DisableIPSourceRouting'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
            ValueType = 'Dword'
            ValueName = 'DisableIPSourceRouting'
            ValueData = 2
        }
    }
    
    if ($DisableIPSourceRoutingTcpip6) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\DisableIPSourceRouting'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'
            ValueType = 'Dword'
            ValueName = 'DisableIPSourceRouting'
            ValueData = 2
        }
    }
    
    if ($AuditCredentialValidationSuccess) {
        AuditPolicySubcategory 'Audit Credential Validation (Success) - Inclusion'
        {
            AuditFlag = 'Success'
            Name = 'Credential Validation'
            Ensure = 'Present'
        }
    }
    
    if ($AuditCredentialValidationFailure) {
        AuditPolicySubcategory 'Audit Credential Validation (Failure) - Inclusion'
        {
            AuditFlag = 'Failure'
            Ensure = 'Present'
            Name = 'Credential Validation'
        }
    }

    if ($AuditSecurityGroupManagementSuccess) {
        AuditPolicySubcategory 'Audit Security Group Management (Success) - Inclusion'
        {
            AuditFlag = 'Success'
            Name = 'Security Group Management'
            Ensure = 'Present'
        }
    }
    
    if ($AuditSecurityGroupManagementFailure) {
        AuditPolicySubcategory 'Audit Security Group Management (Failure) - Inclusion'
        {
            AuditFlag = 'Failure'
            Ensure = 'Absent'
            Name = 'Security Group Management'
        }
    }
    
    if ($AuditUserAccountManagementSuccess) {
        AuditPolicySubcategory 'Audit User Account Management (Success) - Inclusion'
        {
            AuditFlag = 'Success'
            Name = 'User Account Management'
            Ensure = 'Present'
        }
    }
    
    if ($AuditUserAccountManagementFailure) {
        AuditPolicySubcategory 'Audit User Account Management (Failure) - Inclusion'
        {
            AuditFlag = 'Failure'
            Ensure = 'Present'
            Name = 'User Account Management'
        }
    }
    
    if ($AuditPnpActivitySuccess) {
        AuditPolicySubcategory 'Audit PNP Activity (Success) - Inclusion'
        {
            AuditFlag = 'Success'
            Name = 'Plug and Play Events'
            Ensure = 'Present'
        }
    }
    
    if ($AuditPnpActivityFailure) {
        AuditPolicySubcategory 'Audit PNP Activity (Failure) - Inclusion'
        {
            AuditFlag = 'Failure'
            Ensure = 'Absent'
            Name = 'Plug and Play Events'
        }
    }
    
    if ($AuditProcessCreationSuccess) {
        AuditPolicySubcategory 'Audit Process Creation (Success) - Inclusion'
        {
            AuditFlag = 'Success'
            Name = 'Process Creation'
            Ensure = 'Present'
        }
    }
    
    if ($AuditProcessCreationFailure) {
        AuditPolicySubcategory 'Audit Process Creation (Failure) - Inclusion'
        {
            AuditFlag = 'Failure'
            Ensure = 'Absent'
            Name = 'Process Creation'
        }
    }
    
    if ($AuditAccountLockoutFailure) {
        AuditPolicySubcategory 'Audit Account Lockout (Failure) - Inclusion'
        {
            AuditFlag = 'Failure'
            Name = 'Account Lockout'
            Ensure = 'Present'
        }
    }
    if ($AuditAccountLockoutSuccess) {
        AuditPolicySubcategory 'Audit Account Lockout (Success) - Inclusion'
        {
            AuditFlag = 'Success'
            Ensure = 'Absent'
            Name = 'Account Lockout'
        }
    }
    
    if ($AuditGroupMembershipSuccess) {
        AuditPolicySubcategory 'Audit Group Membership (Success) - Inclusion'
        {
            AuditFlag = 'Success'
            Name = 'Group Membership'
            Ensure = 'Present'
        }
    }
    
    if ($AuditGroupMembershipFailure) {
        AuditPolicySubcategory 'Audit Group Membership (Failure) - Inclusion'
        {
            AuditFlag = 'Failure'
            Ensure = 'Absent'
            Name = 'Group Membership'
        }
    }
    
    if ($AuditLogonSuccess) {
        AuditPolicySubcategory 'Audit Logon (Success) - Inclusion'
        {
            AuditFlag = 'Success'
            Name = 'Logon'
            Ensure = 'Present'
        }
    }
    
    if ($AuditLogonFailure) {
        AuditPolicySubcategory 'Audit Logon (Failure) - Inclusion'
        {
            AuditFlag = 'Failure'
            Ensure = 'Present'
            Name = 'Logon'
        }
    }
    
    if ($AuditOtherLogonLogoffEventsSuccess) {
        AuditPolicySubcategory 'Audit Other Logon/Logoff Events (Success) - Inclusion'
        {
            AuditFlag = 'Success'
            Name = 'Other Logon/Logoff Events'
            Ensure = 'Present'
        }
    }
    
    if ($AuditOtherLogonLogoffEventsFailure) {
        AuditPolicySubcategory 'Audit Other Logon/Logoff Events (Failure) - Inclusion'
        {
            AuditFlag = 'Failure'
            Ensure = 'Present'
            Name = 'Other Logon/Logoff Events'
        }
    }

    if ($AuditSpecialLogonSuccess) {
        AuditPolicySubcategory 'Audit Special Logon (Success) - Inclusion'
        {
            AuditFlag = 'Success'
            Name = 'Special Logon'
            Ensure = 'Present'
        }
    }
    
    if ($AuditSpecialLogonFailure) {
        AuditPolicySubcategory 'Audit Special Logon (Failure) - Inclusion'
        {
            AuditFlag = 'Failure'
            Ensure = 'Absent'
            Name = 'Special Logon'
        }
    }
    
    if ($AuditDetailedFileShareFailure) {
        AuditPolicySubcategory 'Audit Detailed File Share (Failure) - Inclusion'
        {
            AuditFlag = 'Failure'
            Name = 'Detailed File Share'
            Ensure = 'Present'
        }
    }
    
    if ($AuditDetailedFileShareSuccess) {
        AuditPolicySubcategory 'Audit Detailed File Share (Success) - Inclusion'
        {
            AuditFlag = 'Success'
            Ensure = 'Absent'
            Name = 'Detailed File Share'
        }
    }
    
    if ($AuditFileShareSuccess) {
        AuditPolicySubcategory 'Audit File Share (Success) - Inclusion'
        {
            AuditFlag = 'Success'
            Name = 'File Share'
            Ensure = 'Present'
        }
    }
    
    if ($AuditFileShareFailure) {
        AuditPolicySubcategory 'Audit File Share (Failure) - Inclusion'
        {
            AuditFlag = 'Failure'
            Ensure = 'Present'
            Name = 'File Share'
        }
    }
    
    if ($AuditOtherObjectAccessEventsSuccess) {
        AuditPolicySubcategory 'Audit Other Object Access Events (Success) - Inclusion'
        {
            AuditFlag = 'Success'
            Name = 'Other Object Access Events'
            Ensure = 'Present'
        }
    }
    
    if ($AuditOtherObjectAccessEventsFailure) {
        AuditPolicySubcategory 'Audit Other Object Access Events (Failure) - Inclusion'
        {
            AuditFlag = 'Failure'
            Ensure = 'Present'
            Name = 'Other Object Access Events'
        }
    }
    
    if ($AuditRemovableStorageSuccess) {
        AuditPolicySubcategory 'Audit Removable Storage (Success) - Inclusion'
        {
            AuditFlag = 'Success'
            Name = 'Removable Storage'
            Ensure = 'Present'
        }
    }
    if ($AuditRemovableStorageFailure) {
        AuditPolicySubcategory 'Audit Removable Storage (Failure) - Inclusion'
        {
            AuditFlag = 'Failure'
            Ensure = 'Present'
            Name = 'Removable Storage'
        }
    }
    
    if ($AuditPolicyChangeSuccess) {
        AuditPolicySubcategory 'Audit Audit Policy Change (Success) - Inclusion'
        {
            AuditFlag = 'Success'
            Name = 'Audit Policy Change'
            Ensure = 'Present'
        }
    }
    
    if ($AuditPolicyChangeFailure) {
        AuditPolicySubcategory 'Audit Audit Policy Change (Failure) - Inclusion'
        {
            AuditFlag = 'Failure'
            Ensure = 'Absent'
            Name = 'Audit Policy Change'
        }
    }
    
    if ($AuditAuthenticationPolicyChangeSuccess) {
        AuditPolicySubcategory 'Audit Authentication Policy Change (Success) - Inclusion'
        {
            AuditFlag = 'Success'
            Name = 'Authentication Policy Change'
            Ensure = 'Present'
        }
    }
    
    if ($AuditAuthenticationPolicyChangeFailure) {
        AuditPolicySubcategory 'Audit Authentication Policy Change (Failure) - Inclusion'
        {
            AuditFlag = 'Failure'
            Ensure = 'Absent'
            Name = 'Authentication Policy Change'
        }
    }
    
    if ($AuditMpssvcRuleLevelPolicyChangeSuccess) {
        AuditPolicySubcategory 'Audit MPSSVC Rule-Level Policy Change (Success) - Inclusion'
        {
            AuditFlag = 'Success'
            Name = 'MPSSVC Rule-Level Policy Change'
            Ensure = 'Present'
        }
    }
    
    if ($AuditMpssvcRuleLevelPolicyChangeFailure) {
        AuditPolicySubcategory 'Audit MPSSVC Rule-Level Policy Change (Failure) - Inclusion'
        {
            AuditFlag = 'Failure'
            Ensure = 'Present'
            Name = 'MPSSVC Rule-Level Policy Change'
        }
    }
    
    if ($AuditOtherPolicyChangeEventsFailure) {
        AuditPolicySubcategory 'Audit Other Policy Change Events (Failure) - Inclusion'
        {
            AuditFlag = 'Failure'
            Name = 'Other Policy Change Events'
            Ensure = 'Present'
        }
    }
    if ($AuditOtherPolicyChangeEventsSuccess) {
        AuditPolicySubcategory 'Audit Other Policy Change Events (Success) - Inclusion'
        {
            AuditFlag = 'Success'
            Ensure = 'Absent'
            Name = 'Other Policy Change Events'
        }
    }
    
    if ($AuditSensitivePrivilegeUseSuccess) {
        AuditPolicySubcategory 'Audit Sensitive Privilege Use (Success) - Inclusion'
        {
            AuditFlag = 'Success'
            Name = 'Sensitive Privilege Use'
            Ensure = 'Present'
        }
    }
    
    if ($AuditSensitivePrivilegeUseFailure) {
        AuditPolicySubcategory 'Audit Sensitive Privilege Use (Failure) - Inclusion'
        {
            AuditFlag = 'Failure'
            Ensure = 'Absent'
            Name = 'Sensitive Privilege Use'
        }
    }
    
    if ($AuditOtherSystemEventsSuccess) {
        AuditPolicySubcategory 'Audit Other System Events (Success) - Inclusion'
        {
            AuditFlag = 'Success'
            Name = 'Other System Events'
            Ensure = 'Present'
        }
    }
    
    if ($AuditOtherSystemEventsFailure) {
        AuditPolicySubcategory 'Audit Other System Events (Failure) - Inclusion'
        {
            AuditFlag = 'Failure'
            Ensure = 'Present'
            Name = 'Other System Events'
        }
    }
    
    if ($AuditSecurityStateChangeSuccess) {
        AuditPolicySubcategory 'Audit Security State Change (Success) - Inclusion'
        {
            AuditFlag = 'Success'
            Name = 'Security State Change'
            Ensure = 'Present'
        }
    }
    
    if ($AuditSecurityStateChangeFailure) {
        AuditPolicySubcategory 'Audit Security State Change (Failure) - Inclusion'
        {
            AuditFlag = 'Failure'
            Ensure = 'Absent'
            Name = 'Security State Change'
        }
    }
    
    if ($AuditSecuritySystemExtensionSuccess) {
        AuditPolicySubcategory 'Audit Security System Extension (Success) - Inclusion'
        {
            AuditFlag = 'Success'
            Name = 'Security System Extension'
            Ensure = 'Present'
        }
    }
    
    if ($AuditSecuritySystemExtensionFailure) {
        AuditPolicySubcategory 'Audit Security System Extension (Failure) - Inclusion'
        {
            AuditFlag = 'Failure'
            Ensure = 'Absent'
            Name = 'Security System Extension'
        }
    }
    
    if ($AuditSystemIntegritySuccess) {
        AuditPolicySubcategory 'Audit System Integrity (Success) - Inclusion'
        {
            AuditFlag = 'Success'
            Name = 'System Integrity'
            Ensure = 'Present'
        }
    }
    
    if ($AuditSystemIntegrityFailure) {
        AuditPolicySubcategory 'Audit System Integrity (Failure) - Inclusion'
        {
            AuditFlag = 'Failure'
            Ensure = 'Present'
            Name = 'System Integrity'
        }
    }
    if ($LSAAnonymousNameLookup) {
        SecurityOption 'SecuritySetting(INF): LSAAnonymousNameLookup'
        {
            Network_access_Allow_anonymous_SID_Name_translation = 'Disabled'
            Name = 'Network_access_Allow_anonymous_SID_Name_translation'
        }
    }
    
    if ($CreateGlobalObjects) {
        UserRightsAssignment 'UserRightsAssignment(INF): Create_global_objects'
        {
            Policy = 'Create_global_objects'
            Force = $True
            Identity = @('*S-1-5-32-544', '*S-1-5-6', '*S-1-5-19', '*S-1-5-20')
        }
    }
    
    if ($ActAsPartOfTheOperatingSystem) {
        UserRightsAssignment 'UserRightsAssignment(INF): Act_as_part_of_the_operating_system'
        {
            Policy = 'Act_as_part_of_the_operating_system'
            Force = $True
            Identity = @('')
        }
    }
    
    if ($DenyAccessToThisComputerFromTheNetwork) {
        UserRightsAssignment 'UserRightsAssignment(INF): Deny_access_to_this_computer_from_the_network'
        {
            Policy = 'Deny_access_to_this_computer_from_the_network'
            Force = $True
            Identity = @('*S-1-5-113')
        }
    }
    
    if ($DenyLogOnThroughRemoteDesktopServices) {
        UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_through_Remote_Desktop_Services'
        {
            Policy = 'Deny_log_on_through_Remote_Desktop_Services'
            Force = $True
            Identity = @('*S-1-5-113')
        }
    }
    
    if ($PerformVolumeMaintenanceTasks) {
        UserRightsAssignment 'UserRightsAssignment(INF): Perform_volume_maintenance_tasks'
        {
            Policy = 'Perform_volume_maintenance_tasks'
            Force = $True
            Identity = @('*S-1-5-32-544')
        }
    }
    
    if ($AccessCredentialManagerAsTrustedCaller) {
        UserRightsAssignment 'UserRightsAssignment(INF): Access_Credential_Manager_as_a_trusted_caller'
        {
            Policy = 'Access_Credential_Manager_as_a_trusted_caller'
            Force = $True
            Identity = @('')
        }
    }
    
    if ($CreateTokenObject) {
        UserRightsAssignment 'UserRightsAssignment(INF): Create_a_token_object'
        {
            Policy = 'Create_a_token_object'
            Force = $True
            Identity = @('')
        }
    }
    
    if ($LockPagesInMemory) {
        UserRightsAssignment 'UserRightsAssignment(INF): Lock_pages_in_memory'
        {
            Policy = 'Lock_pages_in_memory'
            Force = $True
            Identity = @('')
        }
    }
    
    if ($CreatePagefile) {
        UserRightsAssignment 'UserRightsAssignment(INF): Create_a_pagefile'
        {
            Policy = 'Create_a_pagefile'
            Force = $True
            Identity = @('*S-1-5-32-544')
        }
    }
    
    if ($DebugPrograms) {
        UserRightsAssignment 'UserRightsAssignment(INF): Debug_programs'
        {
            Policy = 'Debug_programs'
            Force = $True
            Identity = @('*S-1-5-32-544')
        }
    }
    if ($RestoreFilesAndDirectories) {
        UserRightsAssignment 'UserRightsAssignment(INF): Restore_files_and_directories'
        {
            Policy = 'Restore_files_and_directories'
            Force = $True
            Identity = @('*S-1-5-32-544')
        }
    }
    
    if ($TakeOwnershipOfFilesOrOtherObjects) {
        UserRightsAssignment 'UserRightsAssignment(INF): Take_ownership_of_files_or_other_objects'
        {
            Policy = 'Take_ownership_of_files_or_other_objects'
            Force = $True
            Identity = @('*S-1-5-32-544')
        }
    }
    
    if ($AccessThisComputerFromTheNetwork) {
        UserRightsAssignment 'UserRightsAssignment(INF): Access_this_computer_from_the_network'
        {
            Policy = 'Access_this_computer_from_the_network'
            Force = $True
            Identity = @('*S-1-5-32-544', '*S-1-5-32-555')
        }
    }
    
    if ($EnableTrustedForDelegation) {
        UserRightsAssignment 'UserRightsAssignment(INF): Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
        {
            Policy = 'Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
            Force = $True
            Identity = @('')
        }
    }
    
    if ($AllowLogOnLocally) {
        UserRightsAssignment 'UserRightsAssignment(INF): Allow_log_on_locally'
        {
            Policy = 'Allow_log_on_locally'
            Force = $True
            Identity = @('*S-1-5-32-544', '*S-1-5-32-545')
        }
    }
    
    if ($ModifyFirmwareEnvironmentValues) {
        UserRightsAssignment 'UserRightsAssignment(INF): Modify_firmware_environment_values'
        {
            Policy = 'Modify_firmware_environment_values'
            Force = $True
            Identity = @('*S-1-5-32-544')
        }
    }
    
    if ($BackUpFilesAndDirectories) {
        UserRightsAssignment 'UserRightsAssignment(INF): Back_up_files_and_directories'
        {
            Policy = 'Back_up_files_and_directories'
            Force = $True
            Identity = @('*S-1-5-32-544')
        }
    }
    
    if ($ManageAuditingAndSecurityLog) {
        UserRightsAssignment 'UserRightsAssignment(INF): Manage_auditing_and_security_log'
        {
            Policy = 'Manage_auditing_and_security_log'
            Force = $True
            Identity = @('*S-1-5-32-544')
        }
    }
    
    if ($ProfileSingleProcess) {
        UserRightsAssignment 'UserRightsAssignment(INF): Profile_single_process'
        {
            Policy = 'Profile_single_process'
            Force = $True
            Identity = @('*S-1-5-32-544')
        }
    }

    if ($LoadAndUnloadDeviceDrivers) {
        UserRightsAssignment 'UserRightsAssignment(INF): Load_and_unload_device_drivers'
        {
            Policy = 'Load_and_unload_device_drivers'
            Force = $True
            Identity = @('*S-1-5-32-544')
        }
    }
    
    if ($ForceShutdownFromRemoteSystem) {
        UserRightsAssignment 'UserRightsAssignment(INF): Force_shutdown_from_a_remote_system'
        {
            Policy = 'Force_shutdown_from_a_remote_system'
            Force = $True
            Identity = @('*S-1-5-32-544')
        }
    }
    
    if ($CreatePermanentSharedObjects) {
        UserRightsAssignment 'UserRightsAssignment(INF): Create_permanent_shared_objects'
        {
            Policy = 'Create_permanent_shared_objects'
            Force = $True
            Identity = @('')
        }
    }
    
    if ($ImpersonateClientAfterAuthentication) {
        UserRightsAssignment 'UserRightsAssignment(INF): Impersonate_a_client_after_authentication'
        {
            Policy = 'Impersonate_a_client_after_authentication'
            Force = $True
            Identity = @('*S-1-5-32-544', '*S-1-5-6', '*S-1-5-19', '*S-1-5-20')
        }
    }
    
    if ($DomainMemberRequireStrongSessionKey) {
        SecurityOption 'SecurityRegistry(INF): Domain_member_Require_strong_Windows_2000_or_later_session_key'
        {
            Name = 'Domain_member_Require_strong_Windows_2000_or_later_session_key'
            Domain_member_Require_strong_Windows_2000_or_later_session_key = 'Enabled'
        }
    }
    
    if ($AuditForceAuditPolicy) {
        SecurityOption 'SecurityRegistry(INF): Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings'
        {
            Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings = 'Enabled'
            Name = 'Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings'
        }
    }
    
    if ($NetworkAccessDoNotAllowAnonymousEnumeration) {
        SecurityOption 'SecurityRegistry(INF): Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares'
        {
            Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares = 'Enabled'
            Name = 'Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares'
        }
    }
    
    if ($UACOnlyElevateUIAccessAppInSecureLocations) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations'
        {
            Name = 'User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations'
            User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations = 'Enabled'
        }
    }
    
    if ($UACBehaviorOfElevationPromptForStandardUsers) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users'
        {
            Name = 'User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users'
            User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users = 'Automatically deny elevation request'
        }
    }
    
    if ($InteractiveLogonSmartCardRemovalBehavior) {
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Smart_card_removal_behavior'
        {
            Name = 'Interactive_logon_Smart_card_removal_behavior'
            Interactive_logon_Smart_card_removal_behavior = 'Lock workstation'
        }
    }
    
    if ($DomainMemberEncryptOrSignSecureChannelData) {
        SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always'
         {
              Name = 'Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always'
              Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always = 'Enabled'
         }
    }

    if ($DomainMemberDisableMachineAccountPasswordChanges) {
        SecurityOption 'SecurityRegistry(INF): Domain_member_Disable_machine_account_password_changes'
        {
            Name = 'Domain_member_Disable_machine_account_password_changes'
            Domain_member_Disable_machine_account_password_changes = 'Disabled'
        }
    }
    
    if ($UACBehaviorOfElevationPromptForAdministrators) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode'
        {
            Name = 'User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode'
            User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode = 'Prompt for consent on the secure desktop'
        }
    }
    
    if ($UACAdminApprovalModeForBuiltInAdministrator) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account'
        {
            Name = 'User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account'
            User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account = 'Enabled'
        }
    }
    
    if ($DomainMemberDigitallySignSecureChannelData) {
        SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_sign_secure_channel_data_when_possible'
        {
            Name = 'Domain_member_Digitally_sign_secure_channel_data_when_possible'
            Domain_member_Digitally_sign_secure_channel_data_when_possible = 'Enabled'
        }
    }
    
    if ($NetworkSecurityLDAPClientSigningRequirements) {
        SecurityOption 'SecurityRegistry(INF): Network_security_LDAP_client_signing_requirements'
        {
            Name = 'Network_security_LDAP_client_signing_requirements'
            Network_security_LDAP_client_signing_requirements = 'Negotiate Signing'
        }
    }
    
    if ($SendUnencryptedPasswordToThirdPartySMBServers) {
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers'
        {
            Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers = 'Disabled'
            Name = 'Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers'
        }
    }
    
    if ($DoNotStoreLANManagerHashOnNextPasswordChange) {
        SecurityOption 'SecurityRegistry(INF): Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change'
        {
            Name = 'Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change'
            Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change = 'Enabled'
        }
    }
    if ($MinimumSessionSecurityForNTLM) {
        SecurityOption 'SecurityRegistry(INF): Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients'
        {
            Name = 'Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients'
            Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients = 'Both options checked'
        }
    }
    
    if ($MachineInactivityLimit) {
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Machine_inactivity_limit'
        {
            Name = 'Interactive_logon_Machine_inactivity_limit'
            Interactive_logon_Machine_inactivity_limit = '900'
        }
    }
    
    if ($RestrictClientsAllowedToMakeRemoteCallsToSAM) {
        SecurityOption 'SecurityRegistry(INF): Network_access_Restrict_clients_allowed_to_make_remote_calls_to_SAM'
        {
            Network_access_Restrict_clients_allowed_to_make_remote_calls_to_SAM = 'O:BAG:BAD:(A;;RC;;;BA)'
            Name = 'Network_access_Restrict_clients_allowed_to_make_remote_calls_to_SAM'
        }
    }
    
    if ($DigitallyEncryptSecureChannelData) {
        SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_encrypt_secure_channel_data_when_possible'
        {
            Name = 'Domain_member_Digitally_encrypt_secure_channel_data_when_possible'
            Domain_member_Digitally_encrypt_secure_channel_data_when_possible = 'Enabled'
        }
    }
    
    if ($DetectApplicationInstallationsPromptForElevation) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Detect_application_installations_and_prompt_for_elevation'
        {
            Name = 'User_Account_Control_Detect_application_installations_and_prompt_for_elevation'
            User_Account_Control_Detect_application_installations_and_prompt_for_elevation = 'Enabled'
        }
    }
    
    if ($RestrictAnonymousAccessToNamedPipesAndShares) {
        SecurityOption 'SecurityRegistry(INF): Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares'
        {
            Name = 'Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares'
            Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares = 'Enabled'
        }
    }
    
    if ($DigitallySignCommunicationsAlways) {
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Digitally_sign_communications_always'
        {
            Name = 'Microsoft_network_client_Digitally_sign_communications_always'
            Microsoft_network_client_Digitally_sign_communications_always = 'Enabled'
        }
    }
    if ($NetworkSecurityLANManagerAuthenticationLevel) {
        SecurityOption 'SecurityRegistry(INF): Network_security_LAN_Manager_authentication_level'
        {
            Name = 'Network_security_LAN_Manager_authentication_level'
            Network_security_LAN_Manager_authentication_level = 'Send NTLMv2 responses only. Refuse LM & NTLM'
        }
    }
    
    if ($AccountsLimitLocalAccountUseOfBlankPasswords) {
        SecurityOption 'SecurityRegistry(INF): Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only'
        {
            Name = 'Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only'
            Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only = 'Enabled'
        }
    }
    
    if ($MicrosoftNetworkServerDigitallySignCommunications) {
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Digitally_sign_communications_always'
        {
            Name = 'Microsoft_network_server_Digitally_sign_communications_always'
            Microsoft_network_server_Digitally_sign_communications_always = 'Enabled'
        }
    }
    
    if ($NetworkSecurityMinimumSessionSecurityForNTLM) {
        SecurityOption 'SecurityRegistry(INF): Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers'
        {
            Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers = 'Both options checked'
            Name = 'Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers'
        }
    }
    
    if ($NetworkAccessDoNotAllowAnonymousEnumeration) {
        SecurityOption 'SecurityRegistry(INF): Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts'
        {
            Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts = 'Enabled'
            Name = 'Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts'
        }
    }
    
    if ($StrengthenDefaultPermissionsOfInternalSystemObjects) {
        SecurityOption 'SecurityRegistry(INF): System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links'
        {
            Name = 'System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links'
            System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links = 'Enabled'
        }
    }
    
    if ($NetworkSecurityAllowLocalSystemNullSessionFallback) {
        SecurityOption 'SecurityRegistry(INF): Network_security_Allow_LocalSystem_NULL_session_fallback'
        {
            Network_security_Allow_LocalSystem_NULL_session_fallback = 'Disabled'
            Name = 'Network_security_Allow_LocalSystem_NULL_session_fallback'
        }
    }
    
    if ($UACRunAllAdministratorsInAdminApprovalMode) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode'
        {
            Name = 'User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode'
            User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode = 'Enabled'
        }
    }
    
    if ($UACVirtualizeFileAndRegistryWriteFailures) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations'
        {
            Name = 'User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations'
            User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations = 'Enabled'
        }
    }
    RefreshRegistryPolicy 'ActivateClientSideExtension'
    {
        IsSingleInstance = 'Yes'
    }
}

