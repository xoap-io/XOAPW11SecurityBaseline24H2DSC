# XOAPW11SecurityBaseline24H2DSC

This repository contains the **XOAPW11SecurityBaseline24H2DSC** DSC module. 
It covers all settings from official Microsoft Windows 11 Version 24h2 Security Baseline.

## Code of Conduct

This project has adopted this [Code of Conduct](CODE_OF_CONDUCT.md).

## Contributing

Please check out common DSC Community [contributing guidelines](https://dsccommunity.org/guidelines/contributing).

## Change log

A full list of changes in each version can be found in the  [Releases](https://github.com/xoap-io/XOAPSTIGAugust2023DSC/releases).

## Prerequisites

Be sure that the following DSC modules are installed on your system:

- GPRegistryPolicyDsc (1.2.0)
- AuditPolicyDSC (1.4.0.0)
- SecurityPolicyDSC (2.10.0.0)

## Documentation

The XOAP STIG January 2024 DSC module contains the following resources:

- Bitlocker
- Computer
- CredentialGuard
- DomainSecurity
- InternetExplorer11
- WindowsDefender

## Configuration example

To implement the Windows 11 24H2 Security Baseline module, add the following resources to your DSC configuration and adjust accordingly:

### Bitlocker

```PowerShell
Configuration 'XOAPW11SecurityBaseline24H2DSC'
{
    Import-DSCResource -Module 'XOAPW11SecurityBaseline24H2DSC' -Name 'Bitlocker' -ModuleVersion '0.0.1'

    Node 'XOAPW11SecurityBaseline24H2DSC'
    {
        Bitlocker 'Example'
        {
            UseEnhancedPin = $true,
            RDVDenyCrossOrg = $true,
            DisableExternalDMAUnderLock = $true,
            RDVDenyWriteAccess = $true,   
            DenyDeviceClasses = $true,    
            DenyDeviceClassesRetroactive = $true,   
            AllowMediaWriteAccess = $false
        }

    }
}
XOAPW11SecurityBaseline24H2DSC -OutputPath 'C:\XOAPW11SecurityBaseline24H2DSC'
