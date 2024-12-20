configuration CredentialGuard
{
    param(
        [switch]$EnableVirtualizationBasedSecurity = $true,
        [switch]$RequirePlatformSecurityFeatures = $true,
        [switch]$HypervisorEnforcedCodeIntegrity = $true,
        [switch]$HVCIMATRequired = $true,
        [switch]$LsaCfgFlags = $true,
        [switch]$MachineIdentityIsolation = $true,
        [switch]$ConfigureSystemGuardLaunch = $true,
        [switch]$ConfigureKernelShadowStacksLaunch = $true
    )

	Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'
	Import-DSCResource -ModuleName 'AuditPolicyDSC'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC'

    if ($EnableVirtualizationBasedSecurity) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\EnableVirtualizationBasedSecurity'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
            ValueType = 'Dword'
            ValueName = 'EnableVirtualizationBasedSecurity'
            ValueData = 1
        }
    }
    
    if ($RequirePlatformSecurityFeatures) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\RequirePlatformSecurityFeatures'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
            ValueType = 'Dword'
            ValueName = 'RequirePlatformSecurityFeatures'
            ValueData = 1
        }
    }
    
    if ($HypervisorEnforcedCodeIntegrity) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\HypervisorEnforcedCodeIntegrity'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
            ValueType = 'Dword'
            ValueName = 'HypervisorEnforcedCodeIntegrity'
            ValueData = 1
        }
    }
    
    if ($HVCIMATRequired) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\HVCIMATRequired'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
            ValueType = 'Dword'
            ValueName = 'HVCIMATRequired'
            ValueData = 1
        }
    }
    if ($LsaCfgFlags) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\LsaCfgFlags'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
            ValueType = 'Dword'
            ValueName = 'LsaCfgFlags'
            ValueData = 1
        }
    }
    
    if ($MachineIdentityIsolation) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\MachineIdentityIsolation'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
            ValueType = 'Dword'
            ValueName = 'MachineIdentityIsolation'
            ValueData = 3
        }
    }
    
    if ($ConfigureSystemGuardLaunch) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\ConfigureSystemGuardLaunch'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
            ValueType = 'Dword'
            ValueName = 'ConfigureSystemGuardLaunch'
            ValueData = 1
        }
    }
    
    if ($ConfigureKernelShadowStacksLaunch) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\ConfigureKernelShadowStacksLaunch'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
            ValueType = 'Dword'
            ValueName = 'ConfigureKernelShadowStacksLaunch'
            ValueData = 1
        }
    }

    RefreshRegistryPolicy 'ActivateClientSideExtension'
    {
        IsSingleInstance = 'Yes'
    }

}

