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
