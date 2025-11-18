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
        name: "Skript-gg",
        description: "Skript-gg Cheat Detected",
        rule: function(content) {
            const patterns = [
                "!This program cannot be run in DOS mode.",
                "GetModuleHandleW",
                "GetProcAddress",
                "s0+w9#N",
                "1Si8Z<",
                "C?+/O",
                "Z}drW",
                "address family not supported",
                "invalid string position",
                `<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0" xmlns:asmv3="urn:schemas-microsoft-com:asm.v3"><trustInfo xmlns="urn:schemas-microsoft-com:asm.v3"><security><requestedPrivileges><requestedExecutionLevel level="requireAdministrator" uiAccess="false"></requestedExecutionLevel></requestedPrivileges></security></trustInfo><compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1"><application><supportedOS Id="{e2011457-1546-43c5-a5fe-008deee3d3f0}"></supportedOS><supportedOS Id="{35138b9a-5d96-4fbd-8e2d-a2440225f93a}"></supportedOS><supportedOS Id="{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}"></supportedOS><supportedOS Id="{1f676c76-80e1-4239-95bb-83d0f6d0da78}"></supportedOS><supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"></supportedOS></application></compatibility></assembly>`,
                "iza<",
                "M[P<Z",
                "RL4q5",
                "Complete Object Locator'",
                "L$<;L$P",
                "D8i(u"
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
            
            return apiMatches >= 3;
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
    },
    {
        name: "Possible Ransomware",
        description: "Common Randomware Patterns Detected",
        rule: function(content) {
            const patterns = [
                "How to decrypt files", "Your files are encrypted", "Pay the ransom",
                "Bitcoin wallet", "decryption service", "recover your files",
                "AES256", "RSA2048", "file encryption", ".encrypted", ".locked",
                ".crypted", "WannaCry", "Locky", "CryptoLocker", "Ryuk", "REvil",
                "Maze", "Conti", "encryption key", "decryption key", "ransom note",
                "READ_ME.txt", "HELP_DECRYPT.txt", "RECOVER_FILES.txt",
                "Your files have been encrypted with", 
                "To recover your files you need to pay",
                "Send $1000 in Bitcoin to wallet",
                "All your files have been encrypted",
                "Decryption software can be purchased",
                "Contact us at this email to get the decryption key",
                "AES-256-CBC encrypted", "RSA-2048 encrypted",
                "WannaCry ransomware", "LockBit ransomware", "Conti ransomware",
                "REvil/Sodinokibi", "Maze ransomware", "Ryuk ransomware"
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
        name: "Possible RAT Detection",
        description: "Common RAT Detections Inside File",
        rule: function(content) {
            const patterns = [
                "NanoCore", "Gh0stRAT", "DarkComet", "njRAT", "QuasarRAT",
                "keylogger", "screenshotcapture", "remote desktop", "camcapture",
                "GetAsyncKeyState", "SetWindowsHookEx", "shell.execute",
                "reverse_shell", "backconnect", "C2_server", "command_and_control",
                "victim_id", "bot_id", "server_config", "rat_config", "njRAT Config",
                "AsyncRAT", "Remcos RAT", "NetWire RAT",
                "C2_Server_Address", "Bot_Identifier", "Victim_Machine_ID",
                "Keylogger_Enabled", "Remote_Desktop_Active", "Webcam_Capture",
                "Microphone_Record", "File_Manager_Enabled", "Process_Manager"
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
        name: "Possible Discord Token Logger",
        description: "Common Token Logger Indications",
        rule: function(content) {
            const patterns = [
                "discord.com/api/webhooks", "DiscordToken", "Local Storage/leveldb",
                "Roaming/Discord", "tokens.txt", "discord tokens", "webhook_url",
                "x-super-properties", "authorization", "user-token", "payment_source",
                "billing", "credit_card", "discord_guilds", "discord_friends",
                "harvest_tokens", "steal_tokens", "token_grabber", "discord.py",
                "discord.js", "webhook.send", "hook.php", "api/webhooks",
                "https://discord.com/api/webhooks/",
                "Authorization: ", "User-Agent: DiscordBot",
                "X-Super-Properties:", "discord.com/api/v9/users/@me",
                "Local Storage/leveldb", "Roaming\\\\Discord\\\\Local Storage\\\\leveldb",
                "tokens.txt", "discord_tokens.txt", "grabbed_tokens.txt",
                "DiscordTokenGrabber", "TokenLogger", "WebhookManager"
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
        name: "Possible Crypto Miner",
        description: "Common Crypto Mining Indications",
        rule: function(content) {
            const patterns = [
                "xmr.pool", "moneropool", "nanopool.org", "minexmr.com",
                "cryptonight", "randomx", "argon2", "cpu_miner", "gpu_miner",
                "stratum+tcp", "mining_pool", "getwork", "submit_hash",
                "cpuminer", "cgminer", "bfgminer", "xmrig", "xmr-stak",
                "nicehash", "mining_rig", "hash_rate", "difficulty",
                "block_reward", "crypto_miner", "mining_software",
                "stratum+tcp://xmr.pool.minergate.com",
                "stratum+tcp://pool.minexmr.com",
                "stratum+tcp://xmr-asia1.nanopool.org",
                "stratum+tcp://xmr-us-east1.nanopool.org",
                "stratum+tcp://xmr-eu1.nanopool.org",
                "xmrig.exe", "xmr-stak.exe", "cpuminer-multi",
                "cryptonight_r", "randomx_algorithm", "argon2_chukwa",
                "mining_threads", "cpu_affinity", "gpu_mining_enabled"
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
        name: "Possible Malware",
        description: "Common malware droppers & loaders detected",
        rule: function(content) {
            const patterns = [
                "UPX packed", "PECompact", "ASPack", "Themida", "VMProtect",
                "dropper.exe", "loader.dll", "stub.bin", "payload.dat",
                "stage2.bin", "malware_config", "bot_config", "c2_config",
                "decrypt_payload", "unpack_stage", "inject_payload",
                "malware_family", "trojan_generic", "win32.malware",
                "malicious_payload", "infection_chain", "persistence_setup",
                "UPX0", "UPX1", "UPX2", "PECompact2", "ASPack v2.12",
                "Themida/WinLicense", "VMProtect v3", "Enigma Protector",
                "Armadillo Protection", "Obsidium Protection", "CodeVirtualizer",
                "MPRESS compressed", "FSG compressed", "UPX compressed"
            ];
            
            let matches = 0;
            for (const pattern of patterns) {
                if (content.includes(pattern)) matches++;
            }
            return matches >= 4;
        },
        severity: "danger"
    }
];
