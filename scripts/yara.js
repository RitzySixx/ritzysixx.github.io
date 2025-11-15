// Yara rules based on the provided C++ structure
const yaraRules = [
    {
        name: "Generic Cheat (A)",
        description: "Possible Generic Cheat",
        rule: function(content) {
            const patterns = [
                "This program cannot be run in DOS mode.",
                "dagger", "bottle", "crowbar", "unarmed", "flashlight", "golfclub", "hammer",
                "hatchet", "knuckle", "knine", "machete", "switchblade", "nightstick", "wrench",
                "battleaxe", "poolcue", "stone_hatchet", "pistol", "pistol_mk2", "combatpistol",
                "appistol", "stungun", "pistol50", "snspistol", "snspistol_mk2", "heavypistol",
                "vintagepistol", "flaregun", "marksmanpistol", "revolver", "revolver_mk2",
                "doubleaction", "raypistol", "ceramicpistol", "navyrevolver", "microsmg",
                "smg_mk2", "assaultsmg", "combatpdw", "machinepistol", "minismg", "raycarbine",
                "pumpshotgun", "pumpshotgun_mk2", "sawnoffshotgun", "assaultshotgun",
                "bullpupshotgun", "musket", "heavyshotgun", "dbshotgun", "autoshotgun",
                "assaultrifle", "assaultrifle_mk2", "carbinerifle", "carbinerifle_mk2",
                "advancedrifle", "specialcarbine", "specialcarbine_mk2", "bullpuprifle",
                "bullpuprifle_mk2", "compactrifle", "combatmg", "combatmg_mk2", "gusenberg",
                "sniperrifle", "heavysniper", "heavysniper_mk2", "marksmanrifle",
                "marksmanrifle_mk2", "grenadelauncher", "grenadelauncher_smoke", "minigun",
                "firework", "railgun", "hominglauncher", "compactlauncher", "rayminigun",
                "grenade", "bzgas", "smokegrenade", "flare", "molotov", "stickybomb",
                "proxmine", "snowball", "pipebomb", "general_noclip_enabled",
                "general_noclip_speed", "keybinds_menu_open", "keybinds_aimbot",
                "aimbot_enabled", "aimbot_draw_selected_bone", "aimbot_selected_bone",
                "aimbot_selected_bone_color", "aimbot_smooth_enabled", "aimbot_smooth_speed",
                "aimbot_draw_fov", "aimbot_fov_size", "aimbot_fov_color", "vehicles_enabled",
                "vehicles_range", "vehicles_enable_vehicle_count", "players_enabled",
                "players_range", "players_bones_ebabled", "players_bones_color",
                "players_box_enabled", "players_box_type", "players_box_color",
                "players_health_bar_enabled", "players_health_bar_type",
                "players_health_bar_color", "players_armor_bar_enabled",
                "players_armor_bar_type", "players_armor_bar_color", "players_weapon_enabled",
                "players_weapon_color", "players_distance_enabled", "players_distance_color",
                "players_enable_player_count", "players_enable_admin_count"
            ];
    
            let matches = 0;
            for (const pattern of patterns) {
                if (content.includes(pattern)) matches++;
            }
            return matches >= 6;
        },
        severity: "danger"
    },
    {
        name: "Generic Cheat (B)",
        description: "Possible Generic Cheat",
        rule: function(content) {
            const patterns = [
                "This program cannot be run in DOS mode.",
                "\\config\\config.json",
                "Enabled##Aimbot", 
                "Style##PedVisualsBox"
            ];
    
            let matches = 0;
            for (const pattern of patterns) {
                if (content.includes(pattern)) matches++;
            }
            return matches >= 3;
        },
        severity: "danger"
    },
    {
        name: "Generic Cheat (C)",
        description: "Possible Generic Cheat",
        rule: function(content) {
            const patterns = [
                "This program cannot be run in DOS mode.",
                "<requestedExecutionLevel level='asInvoker' uiAccess='false' />",
                "W1,$_@",
                "14$_A:",
                "AR1,$L", 
                "AR1,$D",
                "1<$A[A",
                "1,$_fA",
                "W1,$fA",
                "$A[fE;",
                "AR1,$I",
                "14$]Hc",
                "U14$fD", 
                "AR1,$A",
                "AR1<$AZ@",
                "1<$AZHc",
                "AS1,$A[@",
                "$A[fD;",
                "1,$fD#",
                "AR1<$fA",
                "AR1,$AZHc"
            ];
            
            let matches = 0;
            for (const pattern of patterns) {
                if (content.includes(pattern)) matches++;
            }
            return matches >= 12;
        },
        severity: "danger"
    },
    {
        name: "Generic Cheat (D)", 
        description: "Possible Generic Cheat",
        rule: function(content) {
            const patterns = [
                "This program cannot be run in DOS mode.",
                "h.rsrc",
                "AS1,$A",
                ".AaVXM",
                "AS1<$I",
                "AS1,$A[Hc",
                "1<$A[Hc", 
                "Oh4e1z",
                "AS1,$fE",
                "AS1<$A",
                "1,$A[A",
                "1<$fA#",
                "AS1,$A[",
                "1,$_Hc",
                "1,$A[Hc",
                "AS1<$fD",
                "AS1,$fA", 
                "14$_Hc"
            ];
            
            let matches = 0;
            for (const pattern of patterns) {
                if (content.includes(pattern)) matches++;
            }
            return matches >= 10;
        },
        severity: "danger"
    },
    {
        name: "Generic Cheat (E)",
        description: "Possible Generic Cheat", 
        rule: function(content) {
            const patterns = [
                "This program cannot be run in DOS mode.",
                "V1<$fA",
                "e14$AYHc",
                "V1<$fD",
                "V1<$^H",
                "81<$fA",
                "14$AYHc",
                "$AYfD;",
                "V1<$^Hc", 
                "O1<$fE",
                "W1,$_fA",
                "AQ14$A",
                "1<$^Hc",
                "AQ14$AY",
                "AZA[fA",
                "AQ14$D",
                "V1<$^f",
                "$AYfA;",
                "AYA^fD", 
                "1<$fE3",
                "1<$^E:"
            ];
            
            let matches = 0;
            for (const pattern of patterns) {
                if (content.includes(pattern)) matches++;
            }
            return matches >= 10;
        },
        severity: "danger"
    },
    {
        name: "Generic Cheat (F)",
        description: "Possible Generic Cheat",
        rule: function(content) {
            const patterns = [
                "This program cannot be run in DOS mode.",
                "1<$[Hc",
                "S1<$fA", 
                "AS1<$A[Hc",
                "14$_E:",
                "$A[fA;",
                "W14$_H",
                "1<$]Hc",
                "W14$_Hc",
                "W14$_fD;",
                "S1<$[Hc",
                "S1<$Hc",
                "U1<$fA", 
                "W1,$_A",
                "AS1<$fD",
                "1<$fE+"
            ];
            
            let matches = 0;
            for (const pattern of patterns) {
                if (content.includes(pattern)) matches++;
            }
            return matches >= 10;
        },
        severity: "danger"
    },
    {
        name: "RevoUninstaller",
        description: "RevoUninstaller Detected",
        rule: function(content) {
            const patterns = [
                "RevoUnin.exe",
                "Revo Uninstaller", 
                "https://www.revouninstaller.com",
                "Revo Uninstaller-command-manager-profile",
                "Revo Uninstaller Pro",
                "https://www.facebook.com/pages/Revo-Uninstaller/53526911789"
            ];
            
            let matches = 0;
            for (const pattern of patterns) {
                if (content.includes(pattern)) matches++;
            }
            return matches >= 3;
        },
        severity: "warning"
    },
    {
        name: "Eulen",
        description: "Eulen Cheat Detected",
        rule: function(content) {
            const patterns = [
                "This program cannot be run in DOS mode.",
                "NtQuerySystemInformation",
                "wESP_", 
                "vAYesp",
                "F<VEH5",
                "D3D11CreateDeviceAndSwapChain",
                "DnsNameCompare_W",
                "HeapFree",
                "InitSecurityInterfaceW",
                "AlphaBlend", 
                "HeapAlloc",
                "D3DCompile",
                "SHELL32.dll",
                "PathRemoveFileSpecW",
                "UxTheme.dll"
            ];
    
            let matches = 0;
            for (const pattern of patterns) {
                if (content.includes(pattern)) matches++;
            }
            return matches >= 10;
        },
        severity: "danger"
    },
    {
        name: "AORIST",
        description: "Free FiveM Cheat",
        rule: function(content) {
            const patterns = [
                "D:\\AORISTFIVEMNEWEST",
                "fivemreworked",
                "aorist.pdb",
                "aorist\\x64\\Release",
                "This program cannot be run in DOS mode."
            ];
            
            let matches = 0;
            for (const pattern of patterns) {
                if (content.includes(pattern)) matches++;
            }
            return matches >= 4;
        },
        severity: "danger"
    },
    {
        name: "Packed File",
        description: "Packed Encrypted File",
        rule: function(content) {
            const bytes = new Uint8Array(content.split('').map(c => c.charCodeAt(0)));
            const fileSize = bytes.length;
 
            if (fileSize < 50 * 1024 || fileSize > 50 * 1024 * 1024)
                return false;
            
            function calculateEntropy(buf) {
                const freq = new Array(256).fill(0);
                for (let i = 0; i < buf.length; i++) freq[buf[i]]++;
    
                let entropy = 0;
                for (let f of freq) {
                    if (f === 0) continue;
                    const p = f / buf.length;
                    entropy -= p * Math.log2(p);
                }
                return entropy;
            }
    
            const entropy = calculateEntropy(bytes);
            return entropy >= 7.2;
        },
        severity: "warning"
    },
    {
        name: "Admin Privileges",
        description: "Requires Admin Privileges To Run",
        rule: function(content) {
            const patterns = [
                "<requestedExecutionLevel level='requireAdministrator' uiAccess='false' />",
                "<requestedPrivileges>",
                "</requestedPrivileges>",
                "CreateProcessAsUserA"
            ];
            
            let matches = 0;
            for (const pattern of patterns) {
                if (content.includes(pattern)) matches++;
            }
            return matches >= 3;
        },
        severity: "warning"
    },
    {
        name: "Memory Injection",
        description: "Memory/DLL injection Process Hollowing",
        rule: function(content) {
            const patterns = [
                "WriteProcessMemory", "CreateRemoteThread", "VirtualAllocEx", "QueueUserAPC",
                "ManualMap", "ReflectiveLoader", "ProcessHollowing", "ThreadHijacking",
                "SetWindowsHookEx", "CallNextHook", "GetAsyncKeyState", "GetKeyState",
                "AttachThreadInput", "GetWindowTextA", "GetForegroundWindow", "FindWindowA",
                "ReadProcessMemory", "IsWow64Process", "Wow64DisableWow64FsRedirection",
                "NtUnmapViewOfSection", "ZwUnmapViewOfSection", "NtAllocateVirtualMemory",
                "NtWriteVirtualMemory", "NtProtectVirtualMemory", "RtlCreateUserThread",
                "RtlEnterCriticalSection", "RtlLeaveCriticalSection", "RtlDeleteCriticalSection"
            ];
    
            let matches = 0;
            for (const pattern of patterns) {
                if (content.includes(pattern)) matches++;
            }
            return matches >= 5;
        },
        severity: "danger"
    },
    {
        name: "Memory Manipulation Hooking",
        description: "Memory manipulation/hooking",
        rule: function(content) {
            const patterns = [
                "VirtualProtect", "VirtualAlloc", "VirtualFree", "HeapCreate", "HeapAlloc",
                "HeapFree", "CreateProcessA", "CreateProcessW", "CreateToolhelp32Snapshot",
                "Module32First", "Module32Next", "Process32First", "Process32Next",
                "GetModuleHandleA", "GetModuleHandleW", "GetProcAddress", "LoadLibraryA",
                "LoadLibraryW", "FreeLibrary", "GetSystemDirectoryA", "GetWindowsDirectoryA",
                "GetTempPathA", "GetTempPathW", "GetCurrentDirectoryA", "GetCurrentDirectoryW",
                "SetCurrentDirectoryA", "SetCurrentDirectoryW", "SearchPathA", "SearchPathW"
            ];
    
            let matches = 0;
            for (const pattern of patterns) {
                if (content.includes(pattern)) matches++;
            }
            return matches >= 6;
        },
        severity: "danger"
    },
    {
        name: "Advanced Memory Manipulation",
        description: "Memory Manipulation & PE Injection & Runtime Patching",
        rule: function(content) {
            const patterns = [
                "MapViewOfFile", "UnmapViewOfFile", "CreateFileMappingA", "CreateFileMappingW",
                "OpenFileMappingA", "OpenFileMappingW", "FlushViewOfFile", "CopyMemory",
                "MoveMemory", "ZeroMemory", "FillMemory", "SecureZeroMemory",
                "GetSystemInfo", "GetNativeSystemInfo", "IsProcessorFeaturePresent",
                "GetSystemTimes", "GetProcessHeap", "GetProcessHeaps", "GetProcessAffinityMask",
                "SetProcessAffinityMask", "GetProcessPriorityBoost", "SetProcessPriorityBoost",
                "GetProcessWorkingSetSize", "SetProcessWorkingSetSize"
            ];
    
            let matches = 0;
            for (const pattern of patterns) {
                if (content.includes(pattern)) matches++;
            }
            return matches >= 5;
        },
        severity: "danger"
    },
    {
        name: "Reflective DLL Loading",
        description: "DLL loading & memory payload execution",
        rule: function(content) {
            const patterns = [
                "ReflectiveDLLMain", "ReflectiveLoad", "ReflectiveInit", "ReflectiveEntry",
                "DLLMain", "DllMainCRTStartup", "DllEntryPoint", "__DllMainCRTStartup",
                "PEB", "TEB", "LdrLoadDll", "LdrUnloadDll", "LdrGetProcedureAddress",
                "LdrInitializeThunk", "LdrLockLoaderLock", "LdrUnlockLoaderLock",
                "NtCreateThreadEx", "RtlCreateUserThread", "ZwCreateThreadEx",
                "NtCreateProcess", "NtCreateProcessEx", "ZwCreateProcess", "ZwCreateProcessEx"
            ];
    
            let matches = 0;
            for (const pattern of patterns) {
                if (content.includes(pattern)) matches++;
            }
            return matches >= 4;
        },
        severity: "danger"
    },
    {
        name: "Memory Decompression",
        description: "Memory Decompression Packing",
        rule: function(content) {
            const patterns = [
                "RtlDecompressBuffer", "RtlDecompressFragment", "RtlGetCompressionWorkSpaceSize",
                "LZWDecompress", "LZNT1Decompress", "LZSS_Decompress", "LZSS_Expand",
                "LZ77_Decompress", "LZ78_Decompress", "LZMA_Decompress", "LZMA2_Decompress",
                "LZMACompress", "LZMA2Compress", "LZ4Compress", "LZ4Uncompress", "LZ4_Compress",
                "LZ4_Uncompress", "LZ4Compress_HC", "LZ4FastDecompress", "LZ4SafeDecompress",
                "LZ4HCDecompress", "LZ4HCDecompressSafe", "LZ4Decompress_safe", "LZ4Decompress_fast",
                "LZ4Decompress_unknownOutputSize", "LZ4Decompress_withPrefix64k",
                "LZ4FrameDecompress", "LZ4FrameCompress", "LZ4FCreateCompressionContext",
                "LZ4FCreateDecompressionContext", "LZ4FFreeCompressionContext", "LZ4FFreeDecompressionContext",
                "LZ4FCompressBegin", "LZ4FCompressUpdate", "LZ4FCompressEnd", "LZ4FDecompress",
                "LZ4_compress_fast", "LZ4_compress_default", "LZ4_compress_limitedOutput",
                "LZ4_decompress_safe", "LZ4_decompress_fast"
            ];
    
            let matches = 0;
            for (const pattern of patterns) {
                if (content.includes(pattern)) matches++;
            }
            return matches >= 3;
        },
        severity: "danger"
    },
    {
        name: "Fileless Execution",
        description: "Fileless Executions Detected",
        rule: function(content) {
            const patterns = [
                "-NoProfile -NonInteractive -EncodedCommand", "-NoProfile -NonInteractive -Command",
                "-ExecutionPolicy Bypass", "-ExecutionPolicy Unrestricted", "-ExecutionPolicy -Scope CurrentUser",
                "pwsh -NoProfile -NonInteractive -EncodedCommand", "-EncodedCommand", "-nop", "-noni",
                "iex", "iwr", "irm", "Get-Content | IEX", "IEX (Get-Content", "Invoke-WebRequest",
                "DownloadString", "DownloadFile", "raw.githubusercontent.com", "gist.githubusercontent.com",
                "ConvertTo-SecureString", "ConvertFrom-SecureString", "Base64String", "ToBase64String",
                "pastebin.com", "ghostbin.co", "controlc.com", "hastebin.com", "webpaste.net",
                "WebClient().DownloadFile", "WebClient.DownloadFile", "Invoke-Expression", "Invoke-RestMethod",
                "New-Object", "System.Net.WebClient", "System.Net.Http.HttpClient"
            ];
    
            let matches = 0;
            for (const pattern of patterns) {
                if (content.includes(pattern)) matches++;
            }
            return matches >= 5;
        },
        severity: "danger"
    },
    {
        name: "PowerShell Obfuscated",
        description: "Obfuscated Scripts & Encoded Patterns",
        rule: function(content) {
            const patterns = [
                "[System.Convert]::FromBase64String", "[Runtime.Interopservices.CharSet]",
                "[System.Text.Encoding]::Unicode.GetString", "[System.Text.Encoding]::ASCII.GetString",
                "[Byte[]]$Assembly", "[System.Reflection.Assembly]::Load", "[System.IO.MemoryStream]",
                "New-Object System.IO.MemoryStream", "New-Object System.Security.Cryptography.AesCryptoServiceProvider",
                "$Signature = [System.Convert]::FromBase64String", "iex $decoded", "invoke-expression $decoded",
                "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12",
                "[System.Net.ServicePointManager]::ServerCertificateValidationCallback",
                "$wc = New-Object System.Net.WebClient", "$wc.Headers.Add('User-Agent', 'Mozilla/5.0')",
                "-windowstyle hidden", "-WindowStyle Hidden", "-WindowStyle Minimized", "-WindowStyle Maximized",
                "Add-Type -AssemblyName System.Windows.Forms", "[System.Windows.Forms.SendKeys]::SendWait"
            ];
    
            let matches = 0;
            for (const pattern of patterns) {
                if (content.includes(pattern)) matches++;
            }
            return matches >= 4;
        },
        severity: "danger"
    },
    {
        name: "Remote Execution",
        description: "Remote Execution & Script Patterns",
        rule: function(content) {
            const patterns = [
                "Invoke-Command", "Enter-PSSession", "New-PSSession", "Remove-PSSession",
                "Invoke-Command -ComputerName", "Invoke-Command -Credential", "Invoke-PSSession",
                "$Session = New-PSSession", "Import-PSSession", "Export-PSSession",
                "Invoke-Command -ScriptBlock", "invoke-command -computername", "invoke-command -credential",
                "New-PSSessionOption", "Connect-PSSession", "Disconnect-PSSession",
                "Enable-PSRemoting", "Set-WSManInstance", "Test-WSMan", "Get-WSManInstance",
                "powershell -Command", "powershell -EncodedCommand", "powershell -File",
                "powershell -Sta", "-MTA", "-STA", "Enable-WSManCredSSP", "Get-PSSnapin"
            ];
    
            let matches = 0;
            for (const pattern of patterns) {
                if (content.includes(pattern)) matches++;
            }
            return matches >= 3;
        },
        severity: "danger"
    },
    {
        name: "Information Extraction",
        description: "Credential Extraction & Dumping",
        rule: function(content) {
            const patterns = [
                "Get-Credential", "ConvertTo-SecureString", "ConvertFrom-SecureString",
                "Export-Clixml", "Import-Clixml", "[System.Management.Automation.PSCredential]",
                "Get-PSDrive", "Get-PSProvider", "Get-ChildItem Cert:\\LocalMachine\\",
                "Get-Process", "Get-WmiObject", "Get-CimInstance", "Get-Service",
                "Get-HotFix", "Get-ComputerInfo", "Get-WinEvent", "Get-EventLog",
                "Get-Process | Select-Object", "Get-Service | Where-Object",
                "$Credential = Get-Credential", "Export-Csv", "ConvertTo-Csv",
                "Out-File", "Set-Content", "Add-Content", "Remove-Item",
                "SeCur32::LogonUser", "Advapi32::LogonUser", "kernel32::OpenProcess",
                "kernel32::ReadProcessMemory", "advapi32::OpenProcessToken"
            ];
    
            let matches = 0;
            for (const pattern of patterns) {
                if (content.includes(pattern)) matches++;
            }
            return matches >= 4;
        },
        severity: "danger"
    },
    {
        name: "Registry Manipulation",
        description: "Registry Manipulation Tampering",
        rule: function(content) {
            const patterns = [
                "New-ItemProperty", "Set-ItemProperty", "Remove-ItemProperty", "Get-ItemProperty",
                "Get-ChildItem HKLM:", "Get-ChildItem HKCU:", "Get-ChildItem HKU:",
                "Get-ChildItem HKCR:", "Get-ChildItem HKCC:", "Set-Location HKLM:",
                "Set-Location HKCU:", "Microsoft\\Windows\\CurrentVersion\\Run",
                "Microsoft\\Windows\\CurrentVersion\\RunOnce", "Microsoft\\Windows\\CurrentVersion\\RunServices",
                "Microsoft\\Windows\\CurrentVersion\\RunServicesOnce", "Software\\Microsoft\\Windows\\CurrentVersion\\",
                "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                "Set-Item -Path", "Remove-Item -Path", "New-Item -Path",
                "reg add", "reg delete", "reg query", "reg export", "reg import",
                "HKEY_LOCAL_MACHINE", "HKEY_CURRENT_USER", "HKEY_USERS", "HKEY_CLASSES_ROOT"
            ];
    
            let matches = 0;
            for (const pattern of patterns) {
                if (content.includes(pattern)) matches++;
            }
            return matches >= 3;
        },
        severity: "danger"
    },
    {
        name: "Network Communication",
        description: "Network Communication & Data Patterns Found",
        rule: function(content) {
            const patterns = [
                "New-Object Net.Sockets.TcpClient", "New-Object Net.Sockets.UdpClient",
                "New-Object Net.Sockets.TcpListener", "New-Object System.Net.Sockets.TcpClient",
                "System.Net.Sockets.TcpClient", "System.Net.Sockets.UdpClient", "System.Net.Sockets.Socket",
                "New-Object System.Net.Sockets.Socket", "[System.Net.Sockets.Socket]",
                "Connect()", "Listen()", "Accept()", "Send()", "Receive()", "SendTo()", "ReceiveFrom()",
                "New-Object System.Net.TcpClient", "New-Object System.Net.UdpClient",
                "Get-Host", "System.Net.Dns.GetHostAddresses", "[Net.DNS]::GetHostAddresses",
                "New-Object System.Net.IPEndPoint", "[System.Net.IPEndPoint]",
                "New-Object System.Net.Sockets.Socket", "[System.Net.Sockets.Socket]::socket",
                "SendMessage", "Send-Data", "Receive-Data", "SendMessageAsync"
            ];
    
            let matches = 0;
            for (const pattern of patterns) {
                if (content.includes(pattern)) matches++;
            }
            return matches >= 4;
        },
        severity: "danger"
    },
    {
        name: "Process Manipulation",
        description: "Process Manipulation & Injection Patterns",
        rule: function(content) {
            const patterns = [
                "Start-Process", "Stop-Process", "Get-Process", "Wait-Process",
                "Suspend-Process", "Resume-Process", "Debug-Process",
                "$Process = Get-Process", "Get-Process | Where-Object", "Get-Process -Name",
                "Get-WmiObject -Class Win32_Process", "Get-CimInstance -Class Win32_Process",
                "Invoke-WmiMethod", "Invoke-CimMethod", "New-CimInstance",
                "$ProcessId = (Get-Process).Id", "Stop-Process -Id", "Kill-Process",
                "Get-Process -IncludeUserName", "Get-Process -FileVersionInfo",
                "Start-Process -WindowStyle Hidden", "Start-Process -Credential",
                "$Handle = $Process.Handle", "$Process.Kill()", "$Process.CloseMainWindow()",
                "[System.Diagnostics.Process]::GetCurrentProcess()", "[System.Diagnostics.Process]::Start()"
            ];
    
            let matches = 0;
            for (const pattern of patterns) {
                if (content.includes(pattern)) matches++;
            }
            return matches >= 3;
        },
        severity: "danger"
    },
    {
        name: "System Manipulation",
        description: "System Manipulation & ADS Detections",
        rule: function(content) {
            const patterns = [
                "Get-ChildItem", "Get-Item", "Get-Content", "Set-Content", "Add-Content", "Clear-Content",
                "New-Item", "Remove-Item", "Copy-Item", "Move-Item", "Rename-Item", "Test-Path",
                "Get-Acl", "Set-Acl", "Get-ChildItem -Path", "Get-ChildItem -Recurse", "Get-ChildItem -Force",
                "Get-Item -Path", "Get-Item -Force", "Get-ItemProperty", "Set-ItemProperty",
                ":$DATA", "Set-Content -Path", "Add-Content -Path", "Get-Content -Path -Stream",
                "Set-Item -Path", "New-Item -Path -Type", "Remove-Item -Path -Recurse",
                "Get-PSDrive", "New-PSDrive", "Remove-PSDrive", "Get-Location", "Set-Location",
                "Resolve-Path", "Split-Path", "Join-Path", "Test-FileExtension", "Test-Path"
            ];
    
            let matches = 0;
            for (const pattern of patterns) {
                if (content.includes(pattern)) matches++;
            }
            return matches >= 4;
        },
        severity: "danger"
    },
    {
        name: "Anti Debug",
        description: "Anti Debugging Detected",
        rule: function(content) {
            // More specific API patterns with fullword matching
            const debugPatterns = [
                "IsDebuggerPresent", 
                "CheckRemoteDebuggerPresent", 
                "OutputDebugString",
                "NtQueryInformationProcess",
                "ZwQueryInformationProcess",
                "BeingDebugged",
                "NtGlobalFlag",
                "DebuggerPresent",
                "ProcessDebugPort"
            ];
            
            let apiMatches = 0;
            for (const pattern of debugPatterns) {
                if (content.includes(pattern)) apiMatches++;
            }
            
            // Lower thresholds for better detection
            return apiMatches >= 2; // Only need 2 anti-debug patterns now
        },
        severity: "danger"
    },
    {
        name: "ImGui Generation",
        description: "Imgui generation detected",
        rule: function(content) {
            // Core ImGui function signatures (more specific)
            const imguiFunctions = [
                "ImGui::Begin",
                "ImGui::Text",
                "ImGui::Button",
                "ImGui::Slider",
                "ImGui::Checkbox",
                "ImGui::SameLine",
                "ImGui::NewFrame",
                "ImGui::Render",
                "ImGui_ImplDX",
                "ImGui_ImplWin32",
                "ImVec2",
                "ImGuiIO",
                "ImGuiStyle",
                "Dear ImGui"
            ];
            
            let functionMatches = 0;
            for (const pattern of imguiFunctions) {
                if (content.includes(pattern)) functionMatches++;
            }
            
            // Much lower threshold - only need 2 ImGui patterns
            return functionMatches >= 2;
        },
        severity: "warning"
    },
    {
        name: "KeyAuth",
        description: "Keyauth Detection in File",
        rule: function(content) {
            // KeyAuth specific patterns - broader detection
            const keyauthPatterns = [
                "keyauth.cc",
                "keyauth.win", 
                "keyauth.com",
                "keyauth.license",
                "keyauth.init",
                "keyauth.check",
                "keyauth.register",
                "keyauth.webhook",
                "keyauth.ban",
                "enckey",
                "ownerid",
                "KeyAuth.App",
                "api/1.0/",
                "response.success"
            ];
            
            let matches = 0;
            for (const pattern of keyauthPatterns) {
                if (content.includes(pattern)) matches++;
            }
            
            // Only need 2 KeyAuth patterns now
            return matches >= 2;
        },
        severity: "warning"
    },
    {
        name: "EAuth",
        description: "EAuth Detection in File",
        rule: function(content) {
            // EAuth specific patterns - broader detection
            const eauthPatterns = [
                "eauth.me",
                "eauth.pro",
                "eauth.gg",
                "api.eauth",
                "EA_Init",
                "EA_Login", 
                "EA_Register",
                "EA_Upgrade",
                "EA_Check",
                "EA_License",
                "EA_HWID",
                "EA_Response",
                "EA_Success",
                "EAClient",
                "EAuth.Application"
            ];
            
            let matches = 0;
            for (const pattern of eauthPatterns) {
                if (content.includes(pattern)) matches++;
            }
            
            // Only need 2 EAuth patterns now
            return matches >= 2;
        },
        severity: "warning"
    }
];
