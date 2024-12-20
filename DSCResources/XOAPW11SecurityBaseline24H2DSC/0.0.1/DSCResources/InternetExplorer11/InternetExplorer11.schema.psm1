configuration InternetExplorer11
{
    param(
        [bool]$RunThisTimeEnabled = $true,
        [bool]$VersionCheckEnabled = $true,
        [bool]$RunInvalidSignatures = $true,
        [bool]$CheckExeSignatures = $true,
        [bool]$Isolation64Bit = $true,
        [bool]$DisableEPMCompat = $true,
        [bool]$Isolation = $true,
        [bool]$FeatureControlDisableMKProtocolReserved = $true,
        [bool]$FeatureControlDisableMKProtocolIexplore = $true,
        [bool]$FeatureControlDisableMKProtocolExplorer = $true,
        [bool]$FeatureMIMEHandlingExplorer = $true,
        [bool]$FeatureMIMEHandlingIexplore = $true,
        [bool]$FeatureMIMEHandlingReserved = $true,
        [bool]$FeatureMIMESniffingExplorer = $true,
        [bool]$FeatureMIMESniffingIexplore = $true,
        [bool]$FeatureMIMESniffingReserved = $true,
        [bool]$FeatureRestrictActiveXInstallReserved = $true,
        [bool]$FeatureRestrictActiveXInstallExplorer = $true,
        [bool]$FeatureRestrictActiveXInstallIexplore = $true,
        [bool]$FeatureRestrictFileDownloadReserved = $true,
        [bool]$FeatureRestrictFileDownloadIexplore = $true,
        [bool]$FeatureRestrictFileDownloadExplorer = $true,
        [bool]$FeatureSecurityBandReserved = $true,
        [bool]$FeatureSecurityBandIexplore = $true,
        [bool]$FeatureSecurityBandExplorer = $true,
        [bool]$FeatureWindowRestrictionsIexplore = $true,
        [bool]$FeatureWindowRestrictionsReserved = $true,
        [bool]$FeatureWindowRestrictionsExplorer = $true,
        [bool]$FeatureZoneElevationReserved = $true,
        [bool]$FeatureZoneElevationExplorer = $true,
        [bool]$FeatureZoneElevationIexplore = $true,
        [bool]$PreventOverrideAppRepUnknown = $true,
        [bool]$PreventOverride = $true,
        [bool]$EnabledV9PhishingFilter = $true,
        [bool]$NoCrashDetection = $true,
        [bool]$DisableSecuritySettingsCheck = $true,
        [bool]$BlockNonAdminActiveXInstall = $true,
        [bool]$OnlyUseAXISForActiveXInstall = $true,
        [bool]$SecurityZonesMapEdit = $true,
        [bool]$SecurityOptionsEdit = $true,
        [bool]$SecurityHKLMOnly = $true,
        [bool]$CertificateRevocation = $true,
        [bool]$PreventIgnoreCertErrors = $true,
        [bool]$WarnOnBadCertReceiving = $true,
        [bool]$EnableSSL3Fallback = $true,
        [bool]$SecureProtocols = $true,
        [bool]$LockdownZones0 = $true,
        [bool]$LockdownZones1 = $true,
        [bool]$LockdownZones2 = $true,
        [bool]$LockdownZones3_2301 = $true,
        [bool]$LockdownZones4_2301 = $true,
        [bool]$LockdownZones4_1C00 = $true,
        [bool]$UNCAsIntranet = $true,
        [bool]$Zones0_1C00 = $true,
        [bool]$Zones0_270C = $true,
        [bool]$Zones1_270C = $true,
        [bool]$Zones1_1201 = $true,
        [bool]$Zones1_1C00 = $true,
        [bool]$Zones2_1C00 = $true,
        [bool]$Zones2_270C = $true,
        [bool]$Zones2_1201 = $true,
        [bool]$Zones3_2001 = $true,
        [bool]$Zones3_2102 = $true,
        [bool]$Zones3_1802 = $true,
        [bool]$Zones3_160A = $true,
        [bool]$Zones3_1201 = $true,
        [bool]$Zones3_1406 = $true,
        [bool]$Zones3_1804 = $true,
        [bool]$Zones3_2200 = $true,
        [bool]$Zones3_1209 = $true,
        [bool]$Zones3_1206 = $true,
        [bool]$Zones3_1809 = $true,
        [bool]$Zones3_2500 = $true,
        [bool]$Zones3_2103 = $true,
        [bool]$Zones3_1606 = $true,
        [bool]$Zones3_2402 = $true,
        [bool]$Zones3_2004 = $true,
        [bool]$Zones3_1C00 = $true,
        [bool]$Zones3_1001 = $true,
        [bool]$Zones3_1A00 = $true,
        [bool]$Zones3_2708 = $true,
        [bool]$Zones3_1004 = $true,
        [bool]$Zones3_120b = $true,
        [bool]$Zones3_1407 = $true,
        [bool]$Zones3_1409 = $true,
        [bool]$Zones3_270C = $true,
        [bool]$Zones3_1607 = $true,
        [bool]$Zones3_2709 = $true,
        [bool]$Zones3_2101 = $true,
        [bool]$Zones3_2301 = $true,
        [bool]$Zones3_1806 = $true,
        [bool]$Zones3_120C = $true,
        [bool]$Zones3_140C = $true,
        [bool]$Zones4_1608 = $true,
        [bool]$Zones4_1201 = $true,
        [bool]$Zones4_1001 = $true,
        [bool]$Zones4_1607 = $true,
        [bool]$Zones4_120b = $true,
        [bool]$Zones4_1809 = $true,
        [bool]$Zones4_1004 = $true,
        [bool]$Zones4_1606 = $true,
        [bool]$Zones4_1407 = $true,
        [bool]$Zones4_160A = $true,
        [bool]$Zones4_1406 = $true,
        [bool]$Zones4_2102 = $true,
        [bool]$Zones4_2004 = $true,
        [bool]$Zones4_2200 = $true,
        [bool]$Zones4_2000 = $true,
        [bool]$Zones4_1402 = $true,
        [bool]$Zones4_1803 = $true,
        [bool]$Zones4_2402 = $true,
        [bool]$Zones4_1400 = $true,
        [bool]$Zones4_1A00 = $true,
        [bool]$Zones4_2001 = $true,
        [bool]$Zones4_2500 = $true,
        [bool]$Zones4_1409 = $true,
        [bool]$Zones4_1C00 = $true,
        [bool]$Zones4_1209 = $true,
        [bool]$Zones4_270C = $true,
        [bool]$Zones4_1206 = $true,
        [bool]$Zones4_2708 = $true,
        [bool]$Zones4_1802 = $true,
        [bool]$Zones4_2103 = $true,
        [bool]$Zones4_2709 = $true,
        [bool]$Zones4_1405 = $true,
        [bool]$Zones4_2101 = $true,
        [bool]$Zones4_2301 = $true,
        [bool]$Zones4_1200 = $true,
        [bool]$Zones4_1804 = $true,
        [bool]$Zones4_1806 = $true,
        [bool]$Zones4_120c = $true,
        [bool]$Zones4_140C = $true
    )

    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'
	Import-DSCResource -ModuleName 'AuditPolicyDSC'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC'

    if ($RunThisTimeEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Ext\RunThisTimeEnabled'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Ext'
            ValueType = 'Dword'
            ValueName = 'RunThisTimeEnabled'
            ValueData = 0
        }
    }
    
    if ($VersionCheckEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Ext\VersionCheckEnabled'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Ext'
            ValueType = 'Dword'
            ValueName = 'VersionCheckEnabled'
            ValueData = 1
        }
    }
    
    if ($RunInvalidSignatures) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Download\RunInvalidSignatures'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Download'
            ValueType = 'Dword'
            ValueName = 'RunInvalidSignatures'
            ValueData = 0
        }
    }
    
    if ($CheckExeSignatures) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Download\CheckExeSignatures'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Download'
            ValueType = 'String'
            ValueName = 'CheckExeSignatures'
            ValueData = 'yes'
        }
    }
    
    if ($Isolation64Bit) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\Isolation64Bit'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main'
            ValueType = 'Dword'
            ValueName = 'Isolation64Bit'
            ValueData = 1
        }
    }
    
    if ($DisableEPMCompat) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\DisableEPMCompat'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main'
            ValueType = 'Dword'
            ValueName = 'DisableEPMCompat'
            ValueData = 1
        }
    }
    
    if ($Isolation) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\Isolation'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main'
            ValueType = 'String'
            ValueName = 'Isolation'
            ValueData = 'PMEM'
        }
    }
    
    if ($FeatureControlDisableMKProtocolReserved) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL\(Reserved)'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL'
            ValueType = 'String'
            ValueName = '(Reserved)'
            ValueData = '1'
        }
    }
    
    if ($FeatureControlDisableMKProtocolIexplore) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL\iexplore.exe'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL'
            ValueType = 'String'
            ValueName = 'iexplore.exe'
            ValueData = '1'
        }
    }
    
    if ($FeatureControlDisableMKProtocolExplorer) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL\explorer.exe'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL'
            ValueType = 'String'
            ValueName = 'explorer.exe'
            ValueData = '1'
        }
    }

    if ($FeatureMIMEHandlingExplorer) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING\explorer.exe'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING'
            ValueType = 'String'
            ValueName = 'explorer.exe'
            ValueData = '1'
        }
    }
    
    if ($FeatureMIMEHandlingIexplore) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING\iexplore.exe'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING'
            ValueType = 'String'
            ValueName = 'iexplore.exe'
            ValueData = '1'
        }
    }
    
    if ($FeatureMIMEHandlingReserved) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING\(Reserved)'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING'
            ValueType = 'String'
            ValueName = '(Reserved)'
            ValueData = '1'
        }
    }
    
    if ($FeatureMIMESniffingExplorer) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING\explorer.exe'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING'
            ValueType = 'String'
            ValueName = 'explorer.exe'
            ValueData = '1'
        }
    }
    
    if ($FeatureMIMESniffingIexplore) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING\iexplore.exe'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING'
            ValueType = 'String'
            ValueName = 'iexplore.exe'
            ValueData = '1'
        }
    }
    if ($FeatureMIMESniffingReserved) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING\(Reserved)'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING'
            ValueType = 'String'
            ValueName = '(Reserved)'
            ValueData = '1'
        }
    }
    
    if ($FeatureRestrictActiveXInstallReserved) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL\(Reserved)'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL'
            ValueType = 'String'
            ValueName = '(Reserved)'
            ValueData = '1'
        }
    }
    
    if ($FeatureRestrictActiveXInstallExplorer) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL\explorer.exe'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL'
            ValueType = 'String'
            ValueName = 'explorer.exe'
            ValueData = '1'
        }
    }
    
    if ($FeatureRestrictActiveXInstallIexplore) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL\iexplore.exe'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL'
            ValueType = 'String'
            ValueName = 'iexplore.exe'
            ValueData = '1'
        }
    }
    
    if ($FeatureRestrictFileDownloadReserved) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD\(Reserved)'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD'
            ValueType = 'String'
            ValueName = '(Reserved)'
            ValueData = '1'
        }
    }
    
    if ($FeatureRestrictFileDownloadIexplore) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD\iexplore.exe'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD'
            ValueType = 'String'
            ValueName = 'iexplore.exe'
            ValueData = '1'
        }
    }
    if ($FeatureRestrictFileDownloadExplorer) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD\explorer.exe'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD'
            ValueType = 'String'
            ValueName = 'explorer.exe'
            ValueData = '1'
        }
    }
    
    if ($FeatureSecurityBandReserved) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND\(Reserved)'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND'
            ValueType = 'String'
            ValueName = '(Reserved)'
            ValueData = '1'
        }
    }
    
    if ($FeatureSecurityBandIexplore) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND\iexplore.exe'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND'
            ValueType = 'String'
            ValueName = 'iexplore.exe'
            ValueData = '1'
        }
    }
    
    if ($FeatureSecurityBandExplorer) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND\explorer.exe'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND'
            ValueType = 'String'
            ValueName = 'explorer.exe'
            ValueData = '1'
        }
    }
    
    if ($FeatureWindowRestrictionsIexplore) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS\iexplore.exe'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS'
            ValueType = 'String'
            ValueName = 'iexplore.exe'
            ValueData = '1'
        }
    }
    if ($FeatureWindowRestrictionsReserved) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS\(Reserved)'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS'
            ValueType = 'String'
            ValueName = '(Reserved)'
            ValueData = '1'
        }
    }
    
    if ($FeatureWindowRestrictionsExplorer) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS\explorer.exe'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS'
            ValueType = 'String'
            ValueName = 'explorer.exe'
            ValueData = '1'
        }
    }
    
    if ($FeatureZoneElevationReserved) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION\(Reserved)'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION'
            ValueType = 'String'
            ValueName = '(Reserved)'
            ValueData = '1'
        }
    }
    
    if ($FeatureZoneElevationExplorer) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION\explorer.exe'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION'
            ValueType = 'String'
            ValueName = 'explorer.exe'
            ValueData = '1'
        }
    }
    
    if ($FeatureZoneElevationIexplore) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION\iexplore.exe'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION'
            ValueType = 'String'
            ValueName = 'iexplore.exe'
            ValueData = '1'
        }
    }
    
    if ($PreventOverrideAppRepUnknown) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter\PreventOverrideAppRepUnknown'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter'
            ValueType = 'Dword'
            ValueName = 'PreventOverrideAppRepUnknown'
            ValueData = 1
        }
    }
    
    if ($PreventOverride) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter\PreventOverride'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter'
            ValueType = 'Dword'
            ValueName = 'PreventOverride'
            ValueData = 1
        }
    }
    if ($EnabledV9PhishingFilter) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter\EnabledV9'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter'
            ValueType = 'Dword'
            ValueName = 'EnabledV9'
            ValueData = 1
        }
    }
    
    if ($NoCrashDetection) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Restrictions\NoCrashDetection'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Restrictions'
            ValueType = 'Dword'
            ValueName = 'NoCrashDetection'
            ValueData = 1
        }
    }
    
    if ($DisableSecuritySettingsCheck) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Security\DisableSecuritySettingsCheck'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Security'
            ValueType = 'Dword'
            ValueName = 'DisableSecuritySettingsCheck'
            ValueData = 0
        }
    }
    
    if ($BlockNonAdminActiveXInstall) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Security\ActiveX\BlockNonAdminActiveXInstall'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Security\ActiveX'
            ValueType = 'Dword'
            ValueName = 'BlockNonAdminActiveXInstall'
            ValueData = 1
        }
    }
    
    if ($OnlyUseAXISForActiveXInstall) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\AxInstaller\OnlyUseAXISForActiveXInstall'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\AxInstaller'
            ValueType = 'Dword'
            ValueName = 'OnlyUseAXISForActiveXInstall'
            ValueData = 1
        }
    }
    
    if ($SecurityZonesMapEdit) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Security_zones_map_edit'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
            ValueType = 'Dword'
            ValueName = 'Security_zones_map_edit'
            ValueData = 1
        }
    }
    if ($SecurityOptionsEdit) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Security_options_edit'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
            ValueType = 'Dword'
            ValueName = 'Security_options_edit'
            ValueData = 1
        }
    }
    
    if ($SecurityHKLMOnly) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Security_HKLM_only'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
            ValueType = 'Dword'
            ValueName = 'Security_HKLM_only'
            ValueData = 1
        }
    }
    
    if ($CertificateRevocation) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\CertificateRevocation'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
            ValueType = 'Dword'
            ValueName = 'CertificateRevocation'
            ValueData = 1
        }
    }
    
    if ($PreventIgnoreCertErrors) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\PreventIgnoreCertErrors'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
            ValueType = 'Dword'
            ValueName = 'PreventIgnoreCertErrors'
            ValueData = 1
        }
    }
    
    if ($WarnOnBadCertReceiving) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\WarnOnBadCertRecving'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
            ValueType = 'Dword'
            ValueName = 'WarnOnBadCertRecving'
            ValueData = 1
        }
    }
    if ($EnableSSL3Fallback) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\EnableSSL3Fallback'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
            ValueType = 'Dword'
            ValueName = 'EnableSSL3Fallback'
            ValueData = 0
        }
    }
    
    if ($SecureProtocols) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\SecureProtocols'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
            ValueType = 'Dword'
            ValueName = 'SecureProtocols'
            ValueData = 2560
        }
    }
    
    if ($LockdownZones0) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\0\1C00'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\0'
            ValueType = 'Dword'
            ValueName = '1C00'
            ValueData = 0
        }
    }
    
    if ($LockdownZones1) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\1\1C00'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\1'
            ValueType = 'Dword'
            ValueName = '1C00'
            ValueData = 0
        }
    }
    
    if ($LockdownZones2) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\2\1C00'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\2'
            ValueType = 'Dword'
            ValueName = '1C00'
            ValueData = 0
        }
    }
    if ($LockdownZones3_2301) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\3\2301'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\3'
            ValueType = 'Dword'
            ValueName = '2301'
            ValueData = 0
        }
    }
    
    if ($LockdownZones4_2301) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4\2301'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4'
            ValueType = 'Dword'
            ValueName = '2301'
            ValueData = 0
        }
    }
    
    if ($LockdownZones4_1C00) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4\1C00'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4'
            ValueType = 'Dword'
            ValueName = '1C00'
            ValueData = 0
        }
    }
    
    if ($UNCAsIntranet) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\UNCAsIntranet'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap'
            ValueType = 'Dword'
            ValueName = 'UNCAsIntranet'
            ValueData = 0
        }
    }
    
    if ($Zones0_1C00) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0\1C00'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0'
            ValueType = 'Dword'
            ValueName = '1C00'
            ValueData = 0
        }
    }
    
    if ($Zones0_270C) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0\270C'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0'
            ValueType = 'Dword'
            ValueName = '270C'
            ValueData = 0
        }
    }
    
    if ($Zones1_270C) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1\270C'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1'
            ValueType = 'Dword'
            ValueName = '270C'
            ValueData = 0
        }
    }
    if ($Zones1_1201) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1\1201'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1'
            ValueType = 'Dword'
            ValueName = '1201'
            ValueData = 3
        }
    }
    
    if ($Zones1_1C00) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1\1C00'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1'
            ValueType = 'Dword'
            ValueName = '1C00'
            ValueData = 65536
        }
    }
    
    if ($Zones2_1C00) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2\1C00'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2'
            ValueType = 'Dword'
            ValueName = '1C00'
            ValueData = 65536
        }
    }
    
    if ($Zones2_270C) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2\270C'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2'
            ValueType = 'Dword'
            ValueName = '270C'
            ValueData = 0
        }
    }
    
    if ($Zones2_1201) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2\1201'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2'
            ValueType = 'Dword'
            ValueName = '1201'
            ValueData = 3
        }
    }
    
    if ($Zones3_2001) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2001'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            ValueName = '2001'
            ValueData = 3
        }
    }
    
    if ($Zones3_2102) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2102'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            ValueName = '2102'
            ValueData = 3
        }
    }
    if ($Zones3_1802) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1802'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            ValueName = '1802'
            ValueData = 3
        }
    }
    
    if ($Zones3_160A) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\160A'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            ValueName = '160A'
            ValueData = 3
        }
    }
    
    if ($Zones3_1201) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1201'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            ValueName = '1201'
            ValueData = 3
        }
    }
    
    if ($Zones3_1406) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1406'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            ValueName = '1406'
            ValueData = 3
        }
    }
    
    if ($Zones3_1804) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1804'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            ValueName = '1804'
            ValueData = 3
        }
    }
    
    if ($Zones3_2200) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2200'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            ValueName = '2200'
            ValueData = 3
        }
    }
    
    if ($Zones3_1209) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1209'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            ValueName = '1209'
            ValueData = 3
        }
    }
    if ($Zones3_1206) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1206'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            ValueName = '1206'
            ValueData = 3
        }
    }
    
    if ($Zones3_1809) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1809'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            ValueName = '1809'
            ValueData = 0
        }
    }
    
    if ($Zones3_2500) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2500'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            ValueName = '2500'
            ValueData = 0
        }
    }
    
    if ($Zones3_2103) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2103'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            ValueName = '2103'
            ValueData = 3
        }
    }
    
    if ($Zones3_1606) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1606'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            ValueName = '1606'
            ValueData = 3
        }
    }
    
    if ($Zones3_2402) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2402'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            ValueName = '2402'
            ValueData = 3
        }
    }
    if ($Zones3_2004) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2004'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            ValueName = '2004'
            ValueData = 3
        }
    }
    
    if ($Zones3_1C00) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1C00'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            ValueName = '1C00'
            ValueData = 0
        }
    }
    
    if ($Zones3_1001) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1001'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            ValueName = '1001'
            ValueData = 3
        }
    }
    
    if ($Zones3_1A00) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1A00'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            ValueName = '1A00'
            ValueData = 65536
        }
    }
    
    if ($Zones3_2708) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2708'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            ValueName = '2708'
            ValueData = 3
        }
    }
    
    if ($Zones3_1004) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1004'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            ValueName = '1004'
            ValueData = 3
        }
    }
    
    if ($Zones3_120b) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\120b'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            ValueName = '120b'
            ValueData = 3
        }
    }

    if ($Zones3_1407) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1407'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            ValueName = '1407'
            ValueData = 3
        }
    }
    
    if ($Zones3_1409) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1409'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            ValueName = '1409'
            ValueData = 0
        }
    }
    
    if ($Zones3_270C) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\270C'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            ValueName = '270C'
            ValueData = 0
        }
    }
    
    if ($Zones3_1607) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1607'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            ValueName = '1607'
            ValueData = 3
        }
    }
    
    if ($Zones3_2709) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2709'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            ValueName = '2709'
            ValueData = 3
        }
    }
    if ($Zones3_2101) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2101'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            ValueName = '2101'
            ValueData = 3
        }
    }
    
    if ($Zones3_2301) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2301'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            ValueName = '2301'
            ValueData = 0
        }
    }
    
    if ($Zones3_1806) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1806'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            ValueName = '1806'
            ValueData = 1
        }
    }
    
    if ($Zones3_120C) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\120c'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            ValueName = '120c'
            ValueData = 3
        }
    }
    
    if ($Zones3_140C) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\140C'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            ValueName = '140C'
            ValueData = 3
        }
    }
    
    if ($Zones4_1608) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1608'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            ValueName = '1608'
            ValueData = 3
        }
    }
    
    if ($Zones4_1201) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1201'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            ValueName = '1201'
            ValueData = 3
        }
    }
    if ($Zones4_1001) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1001'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            ValueName = '1001'
            ValueData = 3
        }
    }
    
    if ($Zones4_1607) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1607'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            ValueName = '1607'
            ValueData = 3
        }
    }
    
    if ($Zones4_120b) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\120b'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            ValueName = '120b'
            ValueData = 3
        }
    }
    
    if ($Zones4_1809) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1809'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            ValueName = '1809'
            ValueData = 0
        }
    }
    
    if ($Zones4_1004) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1004'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            ValueName = '1004'
            ValueData = 3
        }
    }
    
    if ($Zones4_1606) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1606'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            ValueName = '1606'
            ValueData = 3
        }
    }
    
    if ($Zones4_1407) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1407'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            ValueName = '1407'
            ValueData = 3
        }
    }
    
    if ($Zones4_160A) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\160A'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            ValueName = '160A'
            ValueData = 3
        }
    }
    if ($Zones4_1406) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1406'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            ValueName = '1406'
            ValueData = 3
        }
    }
    
    if ($Zones4_2102) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2102'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            ValueName = '2102'
            ValueData = 3
        }
    }
    
    if ($Zones4_2004) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2004'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            ValueName = '2004'
            ValueData = 3
        }
    }
    
    if ($Zones4_2200) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2200'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            ValueName = '2200'
            ValueData = 3
        }
    }
    
    if ($Zones4_2000) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2000'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            ValueName = '2000'
            ValueData = 3
        }
    }
    
    if ($Zones4_1402) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1402'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            ValueName = '1402'
            ValueData = 3
        }
    }
    
    if ($Zones4_1803) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1803'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            ValueName = '1803'
            ValueData = 3
        }
    }
    if ($Zones4_2402) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2402'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            ValueName = '2402'
            ValueData = 3
        }
    }
    
    if ($Zones4_1400) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1400'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            ValueName = '1400'
            ValueData = 3
        }
    }
    
    if ($Zones4_1A00) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1A00'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            ValueName = '1A00'
            ValueData = 196608
        }
    }
    
    if ($Zones4_2001) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2001'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            ValueName = '2001'
            ValueData = 3
        }
    }
    
    if ($Zones4_2500) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2500'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            ValueName = '2500'
            ValueData = 0
        }
    }
    
    if ($Zones4_1409) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1409'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            ValueName = '1409'
            ValueData = 0
        }
    }
    
    if ($Zones4_1C00) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1C00'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            ValueName = '1C00'
            ValueData = 0
        }
    }
    
    if ($Zones4_1209) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1209'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            ValueName = '1209'
            ValueData = 3
        }
    }
    
    if ($Zones4_270C) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\270C'
         {
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueType = 'Dword'
              ValueName = '270C'
              ValueData = 0
         }
    
    }
    if ($Zones4_1206) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1206'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            ValueName = '1206'
            ValueData = 3
        }
    }
    
    if ($Zones4_2708) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2708'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            ValueName = '2708'
            ValueData = 3
        }
    }
    
    if ($Zones4_1802) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1802'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            ValueName = '1802'
            ValueData = 3
        }
    }
    
    if ($Zones4_2103) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2103'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            ValueName = '2103'
            ValueData = 3
        }
    }
    
    if ($Zones4_2709) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2709'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            ValueName = '2709'
            ValueData = 3
        }
    }
    if ($Zones4_1405) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1405'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            ValueName = '1405'
            ValueData = 3
        }
    }
    
    if ($Zones4_2101) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2101'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            ValueName = '2101'
            ValueData = 3
        }
    }
    
    if ($Zones4_2301) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2301'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            ValueName = '2301'
            ValueData = 0
        }
    }
    
    if ($Zones4_1200) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1200'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            ValueName = '1200'
            ValueData = 3
        }
    }
    
    if ($Zones4_1804) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1804'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            ValueName = '1804'
            ValueData = 3
        }
    }
    
    if ($Zones4_1806) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1806'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            ValueName = '1806'
            ValueData = 3
        }
    }
    
    if ($Zones4_120c) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\120c'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            ValueName = '120c'
            ValueData = 3
        }
    }
    
    if ($Zones4_140C) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\140C'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            ValueName = '140C'
            ValueData = 3
        }
    }
    RefreshRegistryPolicy 'ActivateClientSideExtension'
    {
        IsSingleInstance = 'Yes'
    }    
}

