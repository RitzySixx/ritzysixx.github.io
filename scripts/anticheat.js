// Anticheat Detection Patterns Database
const cheatDetections = [
    {
        name: "Generic Menu PTFX Detection",
        description: "Common menu-based cheat using particle effects",
        pattern: "@monitor/resource/menu/client/cl_ptfx.lua:CreatePlayerModePtfxLoop:84:85:116",
        function: "CreateThread",
        hashPattern: "6387d32971b38551c3e994b111ba6787",
        severity: "danger"
    },
    {
        name: "Eulen Menu Detection",
        description: "Eulen cheat menu pattern detected",
        pattern: "eulen/menu/client/cl_main.lua:InitializeMenu:45:50",
        function: "Citizen.CreateThread",
        hashPattern: "e8d4f5a2b1c9e3f7a6b8c2d4e5f1a3b7c9d8e2f",
        severity: "danger"
    },
    {
        name: "RedEngine Menu Detection",
        description: "RedEngine cheat pattern detected",
        pattern: "redengine/menu/client/cl_main.lua:LoadMenu:12:20",
        function: "Citizen.CreateThreadNow",
        hashPattern: "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0",
        severity: "danger"
    },
    {
        name: "Brutan Menu Detection",
        description: "Brutan cheat menu pattern detected",
        pattern: "brutan/menu/client/cl_ui.lua:DrawMenu:100:150",
        function: "Citizen.Wait",
        hashPattern: "9z8y7x6w5v4u3t2s1r0q9p8o7n6m5l4k3j2i1h0",
        severity: "danger"
    }
];

// Function to extract strings from pasted input
function extractStrings(input) {
    // Split by newlines and filter out empty lines
    const lines = input.split('\n').filter(line => line.trim() !== '');
    
    // Remove any "pattern:", "function:", "hashPattern:" labels if present
    const cleanedLines = lines.map(line => {
        return line.replace(/^(pattern:|function:|hashPattern:)\s*/i, '').trim();
    });
    
    return cleanedLines;
}

// Function to match detection against known patterns
function matchDetection(inputStrings) {
    const results = [];
    
    for (const detection of cheatDetections) {
        let matchedFields = 0;
        const matches = {
            pattern: false,
            function: false,
            hash: false
        };
        
        // Check each input string against detection fields
        for (const str of inputStrings) {
            if (str === detection.pattern) {
                matches.pattern = true;
                matchedFields++;
            }
            if (str === detection.function) {
                matches.function = true;
                matchedFields++;
            }
            if (str === detection.hashPattern) {
                matches.hash = true;
                matchedFields++;
            }
        }
        
        // Calculate percentage (33.33% per field)
        const percentage = Math.round((matchedFields / 3) * 100);
        
        results.push({
            detection: detection,
            matches: matches,
            matchedFields: matchedFields,
            totalScore: percentage,
            severity: detection.severity
        });
    }
    
    // Sort by highest score first
    return results.sort((a, b) => b.totalScore - a.totalScore);
}

// Function to get severity class based on score
function getSeverityClass(score, severity) {
    if (score === 100) return 'danger';
    if (score > 0) return 'warning';
    return 'safe';
}

// Function to display known detections in grid
function displayKnownDetections() {
    const grid = document.getElementById('detectionsGrid');
    if (!grid) return;
    
    grid.innerHTML = '';
    
    cheatDetections.forEach(detection => {
        const item = document.createElement('div');
        item.className = 'detection-item';
        item.setAttribute('data-name', detection.name);
        item.innerHTML = `
            <h4>${detection.name}</h4>
            <p>${detection.description}</p>
            <small>Severity: <span class="status ${detection.severity}">${detection.severity}</span></small>
        `;
        
        // Add click handler to fill textarea with this detection
        item.addEventListener('click', () => {
            const textarea = document.getElementById('detectionInput');
            if (textarea) {
                textarea.value = `${detection.pattern}\n${detection.function}\n${detection.hashPattern}`;
            }
        });
        
        grid.appendChild(item);
    });
}

// Function to display analysis results
function displayResults(inputStrings, results) {
    const detectionStatus = document.getElementById('detectionStatus');
    const matchPercentage = document.getElementById('matchPercentage');
    const progressBar = document.getElementById('progressBar');
    const matchDetails = document.getElementById('matchDetails');
    const verdictBox = document.getElementById('verdictBox');
    
    if (!results || results.length === 0 || results[0].totalScore === 0) {
        matchPercentage.textContent = '0%';
        progressBar.style.width = '0%';
        progressBar.style.background = 'linear-gradient(to right, #2962ff, #bbdefb)';
        
        matchDetails.innerHTML = `
            <div style="grid-column: span 3; text-align: center; padding: 20px;">
                <p>No matches found in database</p>
            </div>
        `;
        
        verdictBox.innerHTML = '<span class="status safe">NO MATCHES FOUND</span>';
        detectionStatus.style.display = 'block';
        return;
    }
    
    const bestMatch = results[0];
    matchPercentage.textContent = `${bestMatch.totalScore}%`;
    progressBar.style.width = `${bestMatch.totalScore}%`;
    
    // Change progress bar color based on score
    if (bestMatch.totalScore === 100) {
        progressBar.style.background = 'linear-gradient(to right, #ff1744, #ff5252)';
    } else if (bestMatch.totalScore > 0) {
        progressBar.style.background = 'linear-gradient(to right, #ffab00, #ffc107)';
    } else {
        progressBar.style.background = 'linear-gradient(to right, #2962ff, #bbdefb)';
    }
    
    // Display match details
    matchDetails.innerHTML = '';
    
    // Show input strings
    const inputDiv = document.createElement('div');
    inputDiv.style.gridColumn = 'span 3';
    inputDiv.style.background = 'rgba(10, 14, 23, 0.5)';
    inputDiv.style.padding = '15px';
    inputDiv.style.borderRadius = '10px';
    inputDiv.style.marginBottom = '10px';
    
    let inputHtml = '<h4 style="color: var(--light-blue); margin-bottom: 10px;">Analyzed Strings:</h4>';
    inputStrings.forEach((str, index) => {
        inputHtml += `<p><strong>String ${index + 1}:</strong> ${str}</p>`;
    });
    
    inputDiv.innerHTML = inputHtml;
    matchDetails.appendChild(inputDiv);
    
    // Show best match details
    const matchDiv = document.createElement('div');
    matchDiv.style.gridColumn = 'span 3';
    matchDiv.innerHTML = `<h4 style="color: var(--light-blue); margin: 10px 0;">Best Match: ${bestMatch.detection.name}</h4>`;
    matchDetails.appendChild(matchDiv);
    
    // Pattern match
    const patternItem = document.createElement('div');
    patternItem.className = `match-item ${bestMatch.matches.pattern ? 'matched' : ''}`;
    patternItem.innerHTML = `
        <h4>Pattern Match</h4>
        <div class="match-value">${bestMatch.matches.pattern ? '✓ MATCHED' : '✗ NO MATCH'}</div>
        <div>Expected: ${bestMatch.detection.pattern.substring(0, 30)}${bestMatch.detection.pattern.length > 30 ? '...' : ''}</div>
    `;
    matchDetails.appendChild(patternItem);
    
    // Function match
    const functionItem = document.createElement('div');
    functionItem.className = `match-item ${bestMatch.matches.function ? 'matched' : ''}`;
    functionItem.innerHTML = `
        <h4>Function Match</h4>
        <div class="match-value">${bestMatch.matches.function ? '✓ MATCHED' : '✗ NO MATCH'}</div>
        <div>Expected: ${bestMatch.detection.function}</div>
    `;
    matchDetails.appendChild(functionItem);
    
    // Hash match
    const hashItem = document.createElement('div');
    hashItem.className = `match-item ${bestMatch.matches.hash ? 'matched' : ''}`;
    hashItem.innerHTML = `
        <h4>Hash Match</h4>
        <div class="match-value">${bestMatch.matches.hash ? '✓ MATCHED' : '✗ NO MATCH'}</div>
        <div>Expected: ${bestMatch.detection.hashPattern.substring(0, 20)}...</div>
    `;
    matchDetails.appendChild(hashItem);
    
    // Show other potential matches
    const otherMatches = results.filter((r, index) => index > 0 && r.totalScore > 0);
    if (otherMatches.length > 0) {
        const otherDiv = document.createElement('div');
        otherDiv.style.gridColumn = 'span 3';
        otherDiv.style.marginTop = '15px';
        otherDiv.innerHTML = '<h4 style="color: var(--light-blue);">Other Partial Matches:</h4>';
        
        otherMatches.slice(0, 2).forEach(match => {
            otherDiv.innerHTML += `
                <div style="background: rgba(10, 14, 23, 0.5); padding: 10px; border-radius: 5px; margin-top: 5px;">
                    <strong>${match.detection.name}:</strong> ${match.totalScore}% (${match.matchedFields}/3 fields matched)
                </div>
            `;
        });
        
        matchDetails.appendChild(otherDiv);
    }
    
    // Set verdict
    let verdictText = '';
    if (bestMatch.totalScore === 100) {
        verdictText = `⚠️ CONFIRMED MATCH - ${bestMatch.detection.name}`;
    } else if (bestMatch.totalScore > 0) {
        verdictText = `⚠️ PARTIAL MATCH - ${bestMatch.matchedFields}/3 fields matched with ${bestMatch.detection.name}`;
    } else {
        verdictText = '✓ CLEAN - No matches found';
    }
    
    const severityClass = getSeverityClass(bestMatch.totalScore, bestMatch.severity);
    verdictBox.innerHTML = `<span class="status ${severityClass}">${verdictText}</span>`;
    
    detectionStatus.style.display = 'block';
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    displayKnownDetections();
    
    const analyzeBtn = document.getElementById('analyzeBtn');
    const clearBtn = document.getElementById('clearBtn');
    const detectionInput = document.getElementById('detectionInput');
    
    if (analyzeBtn) {
        analyzeBtn.addEventListener('click', function() {
            const input = detectionInput.value.trim();
            if (!input) {
                alert('Please paste detection strings first');
                return;
            }
            
            const strings = extractStrings(input);
            const results = matchDetection(strings);
            
            displayResults(strings, results);
        });
    }
    
    if (clearBtn) {
        clearBtn.addEventListener('click', function() {
            detectionInput.value = '';
            document.getElementById('detectionStatus').style.display = 'none';
        });
    }
});
