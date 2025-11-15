function copyScript(scriptId, element) {
    const scripts = {
        'script1': 'Get-Process | Format-Table Name, CPU, WorkingSet -AutoSize',
        'script2': 'Get-NetTCPConnection | Where-Object {$_.State -eq "Established"}',
        'script3': 'Get-LocalUser | Format-Table Name, Enabled, LastLogon',
        'script4': 'Get-Service | Where-Object {$_.Status -eq "Running"}',
        'script5': 'Get-ChildItem HKCU:\\ -Recurse | Select-Object Name',
        'script6': 'Get-ChildItem C:\\Windows\\System32 -Filter *.exe',
        'script7': 'Get-EventLog -LogName System -Newest 10',
        'script8': 'Get-WmiObject -Class Win32_ComputerSystem',
        'script9': 'Get-HotFix | Sort-Object InstalledOn -Descending'
    };
    
    const scriptContent = scripts[scriptId] || 'Script not found';
    
    navigator.clipboard.writeText(scriptContent).then(() => {
        const originalText = element.textContent;
        element.textContent = 'Copied!';
        element.style.background = 'linear-gradient(to right, var(--success), #00e676)';
        
        setTimeout(() => {
            element.textContent = originalText;
            element.style.background = 'linear-gradient(to right, var(--primary-blue), var(--accent-blue))';
        }, 2000);
    }).catch(err => {

        console.log('Clipboard copy failed silently');
    });
}

document.addEventListener('DOMContentLoaded', function() {
    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('fileInput');
    const fileInfo = document.getElementById('fileInfo');
    const fileName = document.getElementById('fileName');
    const scanningAnimation = document.getElementById('scanningAnimation');
    const resultsSection = document.getElementById('resultsSection');
    const resultsGrid = document.getElementById('resultsGrid');
    const newScanBtn = document.getElementById('newScanBtn');
    
    // Tab functionality
    const tabButtons = document.querySelectorAll('.tab-btn');
    const tabPanes = document.querySelectorAll('.tab-pane');
    
    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            const tabId = button.getAttribute('data-tab');
            
            // Update active tab button
            tabButtons.forEach(btn => btn.classList.remove('active'));
            button.classList.add('active');
            
            // Show active tab pane
            tabPanes.forEach(pane => pane.classList.remove('active'));
            document.getElementById(tabId).classList.add('active');
        });
    });
    
    // Nested tabs functionality for tools
    const nestedTabButtons = document.querySelectorAll('.nested-tab-btn');
    const nestedTabPanes = document.querySelectorAll('.nested-tab-pane');
    
    nestedTabButtons.forEach(button => {
        button.addEventListener('click', () => {
            const toolCategory = button.getAttribute('data-tool-category');
            
            // Update active nested tab button
            nestedTabButtons.forEach(btn => btn.classList.remove('active'));
            button.classList.add('active');
            
            // Show active nested tab pane
            nestedTabPanes.forEach(pane => pane.classList.remove('active'));
            document.getElementById(toolCategory).classList.add('active');
        });
    });

    // REMOVED the copyScript function from here - it's now outside
    
    dropZone.addEventListener('click', () => fileInput.click());
    
    fileInput.addEventListener('change', function(e) {
        if (this.files.length > 0) {
            handleFile(this.files[0]);
        }
    });
    
    dropZone.addEventListener('dragover', function(e) {
        e.preventDefault();
        this.style.borderColor = '#bbdefb';
        this.style.backgroundColor = 'rgba(41, 98, 255, 0.05)';
    });
    
    dropZone.addEventListener('dragleave', function() {
        this.style.borderColor = '#2962ff';
        this.style.backgroundColor = '';
    });
    
    dropZone.addEventListener('drop', function(e) {
        e.preventDefault();
        this.style.borderColor = '#2962ff';
        this.style.backgroundColor = '';
        
        if (e.dataTransfer.files.length > 0) {
            handleFile(e.dataTransfer.files[0]);
        }
    });
    
    newScanBtn.addEventListener('click', function() {
        resetScanner();
    });
    
    function handleFile(file) {
        fileName.textContent = file.name;
        fileInfo.classList.add('active');
        scanningAnimation.classList.add('active');
        
        setTimeout(() => {
            analyzeFile(file);
        }, 1500);
    }
    
    function analyzeFile(file) {
        const reader = new FileReader();
        
        reader.onload = function(e) {
            const arrayBuffer = e.target.result;
            const bytes = new Uint8Array(arrayBuffer);
        
            let content = "";
            for (let i = 0; i < bytes.length; i++) {
                content += String.fromCharCode(bytes[i]);
            }
        
            const wordArray = CryptoJS.lib.WordArray.create(bytes);
            const sha1Hash = CryptoJS.SHA1(wordArray).toString();
            const sha256Hash = CryptoJS.SHA256(wordArray).toString();
        
            const yaraResults = checkYaraRules(content);
            const hashResults = checkHashes(sha1Hash, sha256Hash);
        
            displayResults(file, sha1Hash, sha256Hash, yaraResults, hashResults);
        
            scanningAnimation.classList.remove('active');
            resultsSection.classList.add('active');
        };
        
        reader.readAsArrayBuffer(file);
    }
    
    function checkYaraRules(content) {
        const results = [];
        yaraRules.forEach(rule => {
            if (rule.rule(content)) {
                results.push({
                    name: rule.name,
                    description: rule.description,
                    severity: rule.severity
                });
            }
        });
        return results;
    }
    
    function checkHashes(sha1, sha256) {
        const sha1Lower = sha1.toLowerCase();
        const sha256Lower = sha256.toLowerCase();
        
        const results = {
            sha1: { 
                match: maliciousHashes.sha1.some(hash => hash.toLowerCase() === sha1Lower), 
                type: "SHA1" 
            },
            sha256: { 
                match: maliciousHashes.sha256.some(hash => hash.toLowerCase() === sha256Lower), 
                type: "SHA256" 
            }
        };
        return results;
    }
    
    function displayResults(file, sha1, sha256, yaraResults, hashResults) {
        resultsGrid.innerHTML = '';
        
        // File Information Card
        const fileInfoCard = document.createElement('div');
        fileInfoCard.className = 'result-card';
        fileInfoCard.innerHTML = `
            <h3><i class="fas fa-info-circle"></i> File Information</h3>
            <p><strong>Name:</strong> ${file.name}</p>
            <p><strong>Size:</strong> ${formatFileSize(file.size)}</p>
            <p><strong>Type:</strong> ${file.type || 'Unknown'}</p>
            <p><strong>Last Modified:</strong> ${new Date(file.lastModified).toLocaleString()}</p>
        `;
        resultsGrid.appendChild(fileInfoCard);
        
        // Hash Information Card
        const hashCard = document.createElement('div');
        hashCard.className = 'result-card';
        
        const sha1Status = hashResults.sha1.match ? 
            '<span class="status danger">KNOWN MALICIOUS</span>' : 
            '<span class="status safe">CLEAN</span>';
        
        const sha256Status = hashResults.sha256.match ? 
            '<span class="status danger">KNOWN MALICIOUS</span>' : 
            '<span class="status safe">CLEAN</span>';
        
        hashCard.innerHTML = `
            <h3><i class="fas fa-fingerprint"></i> Hash Analysis</h3>
            <p><strong>SHA1:</strong> ${sha1}</p>
            <p>${sha1Status}</p>
            <p><strong>SHA256:</strong> ${sha256}</p>
            <p>${sha256Status}</p>
        `;
        resultsGrid.appendChild(hashCard);
        
        // Yara Rules Card
        const yaraCard = document.createElement('div');
        yaraCard.className = 'result-card';
        
        let yaraContent = '';
        if (yaraResults.length > 0) {
            yaraResults.forEach(result => {
                const statusClass = `status ${result.severity}`;
                yaraContent += `
                    <p><strong>${result.name}:</strong> <span class="${statusClass}">MATCH</span></p>
                    <p style="font-size: 0.9rem; opacity: 0.8;">${result.description}</p>
                `;
            });
        } else {
            yaraContent = '<p><span class="status safe">No Yara rule matches found</span></p>';
        }
        
        yaraCard.innerHTML = `
            <h3><i class="fas fa-search"></i> Yara Rules</h3>
            ${yaraContent}
        `;
        resultsGrid.appendChild(yaraCard);
        
        // Security Assessment Card
        const securityCard = document.createElement('div');
        securityCard.className = 'result-card';
        securityCard.innerHTML = `
            <h3><i class="fas fa-chart-line"></i> Security Assessment</h3>
            <p><strong>Security Score:</strong> 
                <span class="status ${calculateSecurityScore(yaraResults, hashResults)}">
                    ${calculateSecurityScore(yaraResults, hashResults).toUpperCase()}
                </span>
            </p>
            <p><strong>Yara Matches:</strong> ${yaraResults.length}</p>
            <p><strong>Hash Matches:</strong> ${(hashResults.sha1.match ? 1 : 0) + (hashResults.sha256.match ? 1 : 0)}</p>
        `;
        resultsGrid.appendChild(securityCard);
    }
    
    function calculateSecurityScore(yaraResults, hashResults) {
        if (hashResults.sha1.match || hashResults.sha256.match) {
            return "danger";
        }
        
        const highSeverityYara = yaraResults.filter(r => r.severity === "danger").length;
        const medSeverityYara = yaraResults.filter(r => r.severity === "warning").length;
        
        if (highSeverityYara > 0) {
            return "danger";
        } else if (medSeverityYara > 1) {
            return "warning";
        } else {
            return "safe";
        }
    }
    
    function formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }
    
    function resetScanner() {
        fileInput.value = '';
        fileInfo.classList.remove('active');
        resultsSection.classList.remove('active');
        scanningAnimation.classList.remove('active');
    }
});