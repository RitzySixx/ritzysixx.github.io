// Yara rules based on the provided C++ structure
const yaraRules = [
    // --- [ PRESERVED RULES: DO NOT MODIFY THESE ] ---
    {
        name: "Generic Cheat (A)",
        description: "Possible Generic Cheat",
        rule: function(content) {
            const patterns = [
                "This program cannot be run in DOS mode.", "dagger", "bottle", "crowbar", "unarmed", "flashlight", "golfclub", "hammer",
                "hatchet", "knuckle", "knine", "machete", "switchblade", "nightstick", "wrench", "battleaxe", "poolcue", "stone_hatchet", "pistol", "pistol_mk2", "combatpistol",
                "appistol", "stungun", "pistol50", "snspistol", "snspistol_mk2", "heavypistol", "vintagepistol", "flaregun", "marksmanpistol", "revolver", "revolver_mk2",
                "doubleaction", "raypistol", "ceramicpistol", "navyrevolver", "microsmg", "smg_mk2", "assaultsmg", "combatpdw", "machinepistol", "minismg", "raycarbine",
                "pumpshotgun", "pumpshotgun_mk2", "sawnoffshotgun", "assaultshotgun", "bullpupshotgun", "musket", "heavyshotgun", "dbshotgun", "autoshotgun",
                "assaultrifle", "assaultrifle_mk2", "carbinerifle", "carbinerifle_mk2", "advancedrifle", "specialcarbine", "specialcarbine_mk2", "bullpuprifle",
                "bullpuprifle_mk2", "compactrifle", "combatmg", "combatmg_mk2", "gusenberg", "sniperrifle", "heavysniper", "heavysniper_mk2", "marksmanrifle",
                "marksmanrifle_mk2", "grenadelauncher", "grenadelauncher_smoke", "minigun", "firework", "railgun", "hominglauncher", "compactlauncher", "rayminigun",
                "grenade", "bzgas", "smokegrenade", "flare", "molotov", "stickybomb", "proxmine", "snowball", "pipebomb", "general_noclip_enabled",
                "general_noclip_speed", "keybinds_menu_open", "keybinds_aimbot", "aimbot_enabled", "aimbot_draw_selected_bone", "aimbot_selected_bone",
                "aimbot_selected_bone_color", "aimbot_smooth_enabled", "aimbot_smooth_speed", "aimbot_draw_fov", "aimbot_fov_size", "aimbot_fov_color", "vehicles_enabled",
                "vehicles_range", "vehicles_enable_vehicle_count", "players_enabled", "players_range", "players_bones_ebabled", "players_bones_color",
                "players_box_enabled", "players_box_type", "players_box_color", "players_health_bar_enabled", "players_health_bar_type",
                "players_health_bar_color", "players_armor_bar_enabled", "players_armor_bar_type", "players_armor_bar_color", "players_weapon_enabled",
                "players_weapon_color", "players_distance_enabled", "players_distance_color", "players_enable_player_count", "players_enable_admin_count"
            ];
            let matches = 0;
            for (const pattern of patterns) { if (content.includes(pattern)) matches++; }
            return matches >= 6;
        },
        severity: "danger"
    },
    {
        name: "Generic Cheat (B)",
        description: "Possible Generic Cheat",
        rule: function(content) {
            const patterns = [ "This program cannot be run in DOS mode.", "\\config\\config.json", "Enabled##Aimbot", "Style##PedVisualsBox" ];
            let matches = 0;
            for (const pattern of patterns) { if (content.includes(pattern)) matches++; }
            return matches >= 3;
        },
        severity: "danger"
    },
    {
        name: "Generic Cheat (C)",
        description: "Possible Generic Cheat",
        rule: function(content) {
            const patterns = [
                "This program cannot be run in DOS mode.", "<requestedExecutionLevel level='asInvoker' uiAccess='false' />", "W1,$_@", "14$_A:",
                "AR1,$L", "AR1,$D", "1<$A[A", "1,$_fA", "W1,$fA", "$A[fE;", "AR1,$I", "14$]Hc", "U14$fD", "AR1,$A", "AR1<$AZ@", "1<$AZHc",
                "AS1,$A[@", "$A[fD;", "1,$fD#", "AR1<$fA", "AR1,$AZHc"
            ];
            let matches = 0;
            for (const pattern of patterns) { if (content.includes(pattern)) matches++; }
            return matches >= 12;
        },
        severity: "danger"
    },
    {
        name: "Generic Cheat (D)", 
        description: "Possible Generic Cheat",
        rule: function(content) {
            const patterns = [ "This program cannot be run in DOS mode.", "h.rsrc", "AS1,$A", ".AaVXM", "AS1<$I", "AS1,$A[Hc", "1<$A[Hc", "Oh4e1z", "AS1,$fE", "AS1<$A", "1,$A[A", "1<$fA#", "AS1,$A[", "1,$_Hc", "1,$A[Hc", "AS1<$fD", "AS1,$fA", "14$_Hc" ];
            let matches = 0;
            for (const pattern of patterns) { if (content.includes(pattern)) matches++; }
            return matches >= 10;
        },
        severity: "danger"
    },
    {
        name: "Generic Cheat (E)",
        description: "Possible Generic Cheat", 
        rule: function(content) {
            const patterns = [ "This program cannot be run in DOS mode.", "V1<$fA", "e14$AYHc", "V1<$fD", "V1<$^H", "81<$fA", "14$AYHc", "$AYfD;", "V1<$^Hc", "O1<$fE", "W1,$_fA", "AQ14$A", "1<$^Hc", "AQ14$AY", "AZA[fA", "AQ14$D", "V1<$^f", "$AYfA;", "AYA^fD", "1<$fE3", "1<$^E:" ];
            let matches = 0;
            for (const pattern of patterns) { if (content.includes(pattern)) matches++; }
            return matches >= 10;
        },
        severity: "danger"
    },
    {
        name: "Generic Cheat (F)",
        description: "Possible Generic Cheat",
        rule: function(content) {
            const patterns = [ "This program cannot be run in DOS mode.", "1<$[Hc", "S1<$fA", "AS1<$A[Hc", "14$_E:", "$A[fA;", "W14$_H", "1<$]Hc", "W14$_Hc", "W14$_fD;", "S1<$[Hc", "S1<$Hc", "U1<$fA", "W1,$_A", "AS1<$fD", "1<$fE+" ];
            let matches = 0;
            for (const pattern of patterns) { if (content.includes(pattern)) matches++; }
            return matches >= 10;
        },
        severity: "danger"
    },
    {
        name: "RevoUninstaller",
        description: "RevoUninstaller Detected",
        rule: function(content) {
            const patterns = [ "RevoUnin.exe", "Revo Uninstaller", "https://www.revouninstaller.com", "Revo Uninstaller-command-manager-profile", "Revo Uninstaller Pro", "https://www.facebook.com/pages/Revo-Uninstaller/53526911789" ];
            let matches = 0;
            for (const pattern of patterns) { if (content.includes(pattern)) matches++; }
            return matches >= 3;
        },
        severity: "warning"
    },
    {
        name: "Eulen",
        description: "Eulen Cheat Detected",
        rule: function(content) {
            const patterns = [ "This program cannot be run in DOS mode.", "NtQuerySystemInformation", "wESP_", "vAYesp", "F<VEH5", "D3D11CreateDeviceAndSwapChain", "DnsNameCompare_W", "HeapFree", "InitSecurityInterfaceW", "AlphaBlend", "HeapAlloc", "D3DCompile", "SHELL32.dll", "PathRemoveFileSpecW", "UxTheme.dll" ];
            let matches = 0;
            for (const pattern of patterns) { if (content.includes(pattern)) matches++; }
            return matches >= 10;
        },
        severity: "danger"
    },
    {
        name: "AORIST",
        description: "Free FiveM Cheat",
        rule: function(content) {
            const patterns = [ "D:\\AORISTFIVEMNEWEST", "fivemreworked", "aorist.pdb", "aorist\\x64\\Release", "This program cannot be run in DOS mode." ];
            let matches = 0;
            for (const pattern of patterns) { if (content.includes(pattern)) matches++; }
            return matches >= 4;
        },
        severity: "danger"
    },
    {
        name: "Skript-gg",
        description: "Skript-gg Cheat Detected",
        rule: function(content) {
            const patterns = [
                "!This program cannot be run in DOS mode.", "GetModuleHandleW", "GetProcAddress", "s0+w9#N", "1Si8Z<", "C?+/O", "Z}drW", "address family not supported", "invalid string position",
                `<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0" xmlns:asmv3="urn:schemas-microsoft-com:asm.v3"><trustInfo xmlns="urn:schemas-microsoft-com:asm.v3"><security><requestedPrivileges><requestedExecutionLevel level="requireAdministrator" uiAccess="false"></requestedExecutionLevel></requestedPrivileges></security></trustInfo><compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1"><application><supportedOS Id="{e2011457-1546-43c5-a5fe-008deee3d3f0}"></supportedOS><supportedOS Id="{35138b9a-5d96-4fbd-8e2d-a2440225f93a}"></supportedOS><supportedOS Id="{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}"></supportedOS><supportedOS Id="{1f676c76-80e1-4239-95bb-83d0f6d0da78}"></supportedOS><supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"></supportedOS></application></compatibility></assembly>`,
                "iza<", "M[P<Z", "RL4q5", "Complete Object Locator'", "L$<;L$P", "D8i(u"
            ];
            let matches = 0;
            for (const pattern of patterns) { if (content.includes(pattern)) matches++; }
            return matches >= 10;
        },
        severity: "danger"
    },

    // --- [ ENHANCED RULES ] ---
    {
        name: "Packed/Encrypted File",
        description: "High Entropy / Packed Data Detected",
        rule: function(content) {
            const bytes = new Uint8Array(content.split('').map(c => c.charCodeAt(0)));
            const fileSize = bytes.length;
            if (fileSize < 20 * 1024 || fileSize > 50 * 1024 * 1024) return false;
            
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
        name: "Admin Privileges Required",
        description: "Manifest requests elevated privileges",
        rule: function(content) {
            const patterns = [
                "level='requireAdministrator'", "level=\"requireAdministrator\"",
                "CreateProcessAsUserA", "CreateProcessWithLogonW", "SeDebugPrivilege"
            ];
            let matches = 0;
            for (const pattern of patterns) { if (content.includes(pattern)) matches++; }
            return matches >= 2;
        },
        severity: "warning"
    },
    {
        name: "Memory Injection / Hollowing",
        description: "Process Hollowing & DLL Injection APIs",
        rule: function(content) {
            const patterns = [
                "WriteProcessMemory", "CreateRemoteThread", "VirtualAllocEx", "QueueUserAPC",
                "NtUnmapViewOfSection", "ZwUnmapViewOfSection", "RtlCreateUserThread",
                "SetThreadContext", "GetThreadContext", "SuspendThread", "ResumeThread",
                "NtCreateThreadEx", "ZwWriteVirtualMemory", "AdjustTokenPrivileges"
            ];
            let matches = 0;
            for (const pattern of patterns) { if (content.includes(pattern)) matches++; }
            return matches >= 4;
        },
        severity: "danger"
    },
    {
        name: "Advanced Memory Manipulation",
        description: "Direct memory mapping and tampering",
        rule: function(content) {
            const patterns = [
                "MapViewOfFile", "CreateFileMappingA", "VirtualProtect", "VirtualProtectEx",
                "ReadProcessMemory", "NtProtectVirtualMemory", "FlushInstructionCache",
                "SetProcessAffinityMask", "LoadLibraryExW", "GetProcAddress", "LdrLoadDll"
            ];
            let matches = 0;
            for (const pattern of patterns) { if (content.includes(pattern)) matches++; }
            return matches >= 5;
        },
        severity: "danger"
    },
    {
        name: "Fileless Execution / LotL",
        description: "PowerShell and Living-off-the-Land techniques",
        rule: function(content) {
            const patterns = [
                "-ExecutionPolicy Bypass", "-nop -w hidden -enc", "powershell -EncodedCommand",
                "Invoke-Expression", "IEX", "Invoke-WebRequest", "System.Net.WebClient",
                "FromBase64String", "WScript.Shell", "regsvr32.exe /s /u /i:", "rundll32.exe"
            ];
            let matches = 0;
            for (const pattern of patterns) { if (content.includes(pattern)) matches++; }
            return matches >= 3;
        },
        severity: "danger"
    },
    {
        name: "Anti-Debugging / Evasion",
        description: "Attempts to detect analysis environments",
        rule: function(content) {
            const patterns = [
                "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
                "OutputDebugString", "FindWindowA", "vmtoolsd.exe", "vboxservice.exe",
                "wireshark", "procmon", "x64dbg", "Process32First", "GetTickCount"
            ];
            let matches = 0;
            for (const pattern of patterns) { if (content.includes(pattern)) matches++; }
            return matches >= 3;
        },
        severity: "danger"
    },
    {
        name: "ImGui Interface Generation",
        description: "Internal overlay generation (Common in cheats)",
        rule: function(content) {
            const patterns = [
                "ImGui::Begin", "ImGui::Text", "ImGui::Button", "ImGui::Render",
                "ImGui_ImplDX11_Init", "ImGui_ImplWin32_Init", "ImGuiIO", "Dear ImGui"
            ];
            let matches = 0;
            for (const pattern of patterns) { if (content.includes(pattern)) matches++; }
            return matches >= 2;
        },
        severity: "warning"
    },
    {
        name: "KeyAuth / EAuth Licensing",
        description: "Common cheat licensing systems",
        rule: function(content) {
            const patterns = [
                "keyauth.cc", "keyauth.win", "ownerid", "enckey", "KeyAuth.App",
                "eauth.me", "eauth.gg", "EA_Init", "EA_License"
            ];
            let matches = 0;
            for (const pattern of patterns) { if (content.includes(pattern)) matches++; }
            return matches >= 2;
        },
        severity: "warning"
    }
];
