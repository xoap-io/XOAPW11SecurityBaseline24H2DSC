configuration Bitlocker
{
    param(
        [bool]$UseEnhancedPin = $true,
        [bool]$RDVDenyCrossOrg = $true,
        [bool]$DisableExternalDMAUnderLock = $true,
        [bool]$RDVDenyWriteAccess = $true,   
        [bool]$DenyDeviceClasses = $true,    
        [bool]$DenyDeviceClassesRetroactive = $true,   
        [bool]$AllowMediaWriteAccess = $false
    )


    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'
    Import-DSCResource -ModuleName 'AuditPolicyDSC'
    Import-DSCResource -ModuleName 'SecurityPolicyDSC'


    if($UseEnhancedPin){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\FVE\UseEnhancedPin'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
            ValueType = 'Dword'
            ValueName = 'UseEnhancedPin'
            ValueData = 1
        }
    }

    if($RDVDenyCrossOrg){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\FVE\RDVDenyCrossOrg'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
            ValueType = 'Dword'
            ValueName = 'RDVDenyCrossOrg'
            ValueData = 0
        }
    }

    if($DisableExternalDMAUnderLock){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\FVE\DisableExternalDMAUnderLock'
        {
             TargetType = 'ComputerConfiguration'
             Key = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
             ValueType = 'Dword'
             ValueName = 'DisableExternalDMAUnderLock'
             ValueData = 1
        }
    }

    if ($RDVDenyWriteAccess) {
        RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Policies\Microsoft\FVE\RDVDenyWriteAccess'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\System\CurrentControlSet\Policies\Microsoft\FVE'
            ValueType = 'Dword'
            ValueName = 'RDVDenyWriteAccess'
            ValueData = 1
        }
    }

    if ($DenyDeviceClasses) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions'
            ValueType = 'Dword'
            ValueName = 'DenyDeviceClasses'
            ValueData = 1
        }
    }

    if ($DenyDeviceClassesRetroactive) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClassesRetroactive'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions'
            ValueType = 'Dword'
            ValueName = 'DenyDeviceClassesRetroactive'
            ValueData = 1
        }
    }

    if ($AllowMediaWriteAccess) {
        RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Policies\Microsoft\FVE\RDVDenyWriteAccess'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\System\CurrentControlSet\Policies\Microsoft\FVE'
            ValueType = 'Dword'
            ValueName = 'RDVDenyWriteAccess'
            ValueData = 0
        }
    }

    RefreshRegistryPolicy 'ActivateClientSideExtension'
    {
        IsSingleInstance = 'Yes'
    }
}

