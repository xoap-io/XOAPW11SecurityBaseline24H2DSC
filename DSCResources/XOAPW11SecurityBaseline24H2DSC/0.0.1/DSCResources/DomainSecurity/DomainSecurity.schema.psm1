configuration DomainSecurity
{
    param(
        [switch]$EnforcePasswordHistory = $true,
        [switch]$StorePasswordsUsingReversibleEncryption = $true,
        [switch]$AccountLockoutDuration = $true,
        [switch]$MinimumPasswordLength = $true,
        [switch]$ResetAccountLockoutCounter = $true,
        [switch]$AccountLockoutThreshold = $true,
        [switch]$PasswordComplexityRequirements = $true
    )

    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'
	Import-DSCResource -ModuleName 'AuditPolicyDSC'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC'

    if ($EnforcePasswordHistory) {
        AccountPolicy 'SecuritySetting(INF): PasswordHistorySize'
        {
            Enforce_password_history = 24
            Name = 'Enforce_password_history'
        }
    }
    
    if ($StorePasswordsUsingReversibleEncryption) {
        AccountPolicy 'SecuritySetting(INF): ClearTextPassword'
        {
            Store_passwords_using_reversible_encryption = 'Disabled'
            Name = 'Store_passwords_using_reversible_encryption'
        }
    }
    
    if ($AccountLockoutDuration) {
        AccountPolicy 'SecuritySetting(INF): LockoutDuration'
        {
            Account_lockout_duration = 10
            Name = 'Account_lockout_duration'
        }
    }
    
    if ($MinimumPasswordLength) {
        AccountPolicy 'SecuritySetting(INF): MinimumPasswordLength'
        {
            Minimum_Password_Length = 14
            Name = 'Minimum_Password_Length'
        }
    }
    
    RefreshRegistryPolicy 'ActivateClientSideExtension'
    {
        IsSingleInstance = 'Yes'
    }

}

