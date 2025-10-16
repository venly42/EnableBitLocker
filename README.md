# EnableBitLocker
Comprehensive script for automating BitLocker encryption and UEFI Secure Boot updates with multi-vendor OEM device BIOS configuration support.
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
