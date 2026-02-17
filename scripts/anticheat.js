// Anticheat Detection Patterns Database
const cheatDetections = [
    {
        name: "Generic Menu PTFX Detection",
        description: "Common menu-based cheat using particle effects",
        pattern: "@monitor/resource/menu/client/cl_ptfx.lua:CreatePlayerModePtfxLoop:84:85:116",
        function: "CreateThread",
        hashPattern: "6387d32971b38551c3e994b111ba6787",
        severity: "danger",
        weight: {
            pattern: 40,
            function: 30,
            hash: 30
        }
    },
    {
        name: "Eulen Menu Detection",
        description: "Eulen cheat menu pattern detected",
        pattern: "eulen/menu/client/cl_main.lua:InitializeMenu:45:50",
        function: "Citizen.CreateThread",
        hashPattern: "e8d4f5a2b1c9e3f7a6b8c2d4e5f1a3b7c9d8e2f",
        severity: "danger",
        weight: {
            pattern: 40,
            function: 30,
            hash: 30
        }
    },
    {
        name: "RedEngine Menu Detection",
        description: "RedEngine cheat pattern detected",
        pattern: "redengine/menu/client/cl_main.lua:LoadMenu:12:20",
        function: "Citizen.CreateThreadNow",
        hashPattern: "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0",
        severity: "danger",
        weight: {
            pattern: 40,
            function: 30,
            hash: 30
        }
    },
    {
        name: "Brutan Menu Detection",
        description: "Brutan cheat menu pattern detected",
        pattern: "brutan/menu/client/cl_ui.lua:DrawMenu:100:150",
        function: "Citizen.Wait",
        hashPattern: "9z8y7x6w5v4u3t2s1r0q9p8o7n6m5l4k3j2i1h0",
        severity: "danger",
        weight: {
            pattern: 40,
            function: 30,
            hash: 30
        }
    },
    {
        name: "Suspicious Thread Creation",
        description: "Unusual thread creation pattern often used in cheats",
        pattern: "client/threads.lua:CreateThread",
        function: "CreateThread",
        hashPattern: "unknown",
        severity: "warning",
        weight: {
            pattern: 40,
            function: 30,
            hash: 30
        }
    },
    {
        name: "Particle Effect Modifier",
        description: "Particle effect manipulation often used in visual cheats",
        pattern: "ptfx_manager.lua:ModifyParticleEffects",
        function: "Citizen.CreateThread",
        hashPattern: "ptfx_modifier_123",
        severity: "warning",
        weight: {
            pattern: 40,
            function: 30,
            hash: 30
        }
    }
];

// Function to extract fields from pasted detection
function extractDetectionFields(input) {
    const lines = input.split('\n');
    let pattern = '';
    let func = '';
    let hash = '';
    
    for (const line of lines) {
        if (line.startsWith('pattern:')) {
            pattern = line.substring(8).trim();
        } else if (line.startsWith('function:')) {
            func = line.substring(9).trim();
        } else if (line.startsWith('hashPattern:')) {
            hash = line.substring(12).trim();
        }
    }
    
    return { pattern, function: func, hashPattern: hash };
}

// Function to calculate similarity between strings
function calculateSimilarity(str1, str2) {
    if (!str1 || !str2) return 0;
    
    // Exact match
    if (str1 === str2) return 100;
    
    // Check if one contains the other
    if (str1.includes(str2) || str2.includes(str1)) {
        const longer = str1.length > str2.length ? str1 : str2;
        const shorter = str1.length > str2.length ? str2 : str1;
        const percentage = (shorter.length / longer.length) * 100;
        return Math.round(percentage);
    }
    
    // Calculate Levenshtein distance for fuzzy matching
    const distance = levenshteinDistance(str1, str2);
    const maxLength = Math.max(str1.length, str2.length);
    const similarity = ((maxLength - distance) / maxLength) * 100;
    
    return Math.round(similarity);
}

// Levenshtein distance algorithm for fuzzy matching
function levenshteinDistance(a, b) {
    if (a.length === 0) return b.length;
    if (b.length === 0) return a.length;
    
    const matrix = [];
    
    for (let i = 0; i <= b.length; i++) {
        matrix[i] = [i];
    }
    
    for (let j = 0; j <= a.length; j++) {
        matrix[0][j] = j;
    }
    
    for (let i = 1; i <= b.length; i++) {
        for (let j = 1; j <= a.length; j++) {
            if (b.charAt(i - 1) === a.charAt(j - 1)) {
                matrix[i][j] = matrix[i - 1][j - 1];
            } else {
                matrix[i][j] = Math.min(
                    matrix[i - 1][j - 1] + 1,
                    Math.min(
                        matrix[i][j - 1] + 1,
                        matrix[i - 1][j] + 1
                    )
                );
            }
        }
    }
    
    return matrix[b.length][a.length];
}

// Function to analyze detection against known patterns
function analyzeDetection(inputPattern, inputFunction, inputHash) {
    const results = [];
    
    for (const detection of cheatDetections) {
        const patternMatch = calculateSimilarity(inputPattern, detection.pattern);
        const functionMatch = calculateSimilarity(inputFunction, detection.function);
        const hashMatch = calculateSimilarity(inputHash, detection.hashPattern);
        
        // Calculate weighted total
        const totalWeight = detection.weight.pattern + detection.weight.function + detection.weight.hash;
        const weightedScore = (
            (patternMatch * detection.weight.pattern) +
            (functionMatch * detection.weight.function) +
            (hashMatch * detection.weight.hash)
        ) / totalWeight;
        
        results.push({
            detection: detection,
            matches: {
                pattern: patternMatch,
                function: functionMatch,
                hash: hashMatch
            },
            totalScore: Math.round(weightedScore),
            severity: detection.severity
        });
    }
    
    // Sort by highest score first
    return results.sort((a, b) => b.totalScore - a.totalScore);
}

// Function to get severity class based on score
function getSeverityClass(score, severity) {
    if (score >= 70) return 'danger';
    if (score >= 30) return 'warning';
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
                textarea.value = `pattern:\n${detection.pattern}\nfunction:\n${detection.function}\nhashPattern:\n${detection.hashPattern}`;
            }
        });
        
        grid.appendChild(item);
    });
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    displayKnownDetections();
    
    const analyzeBtn = document.getElementById('analyzeBtn');
    const clearBtn = document.getElementById('clearBtn');
    const detectionInput = document.getElementById('detectionInput');
    
    if (analyzeBtn) {
        analyzeBtn.addEventListener('click', function() {
            const input = detectionInput.value;
            if (!input.trim()) {
                alert('Please paste a detection pattern first');
                return;
            }
            
            const fields = extractDetectionFields(input);
            const results = analyzeDetection(fields.pattern, fields.function, fields.hashPattern);
            
            displayResults(fields, results);
        });
    }
    
    if (clearBtn) {
        clearBtn.addEventListener('click', function() {
            detectionInput.value = '';
            document.getElementById('detectionStatus').style.display = 'none';
        });
    }
});

// Function to display analysis results
function displayResults(inputFields, results) {
    const detectionStatus = document.getElementById('detectionStatus');
    const matchPercentage = document.getElementById('matchPercentage');
    const progressBar = document.getElementById('progressBar');
    const matchDetails = document.getElementById('matchDetails');
    const verdictBox = document.getElementById('verdictBox');
    
    if (!results || results.length === 0) {
        matchPercentage.textContent = '0%';
        progressBar.style.width = '0%';
        matchDetails.innerHTML = '<p>No matches found</p>';
        verdictBox.innerHTML = '<span class="status safe">No Known Detections</span>';
        detectionStatus.style.display = 'block';
        return;
    }
    
    const bestMatch = results[0];
    matchPercentage.textContent = `${bestMatch.totalScore}%`;
    progressBar.style.width = `${bestMatch.totalScore}%`;
    
    // Change progress bar color based on score
    if (bestMatch.totalScore >= 70) {
        progressBar.style.background = 'linear-gradient(to right, #ff1744, #ff5252)';
    } else if (bestMatch.totalScore >= 30) {
        progressBar.style.background = 'linear-gradient(to right, #ffab00, #ffc107)';
    } else {
        progressBar.style.background = 'linear-gradient(to right, #2962ff, #bbdefb)';
    }
    
    // Display match details
    matchDetails.innerHTML = '';
    
    // Show input fields
    const inputDiv = document.createElement('div');
    inputDiv.style.gridColumn = 'span 3';
    inputDiv.style.background = 'rgba(10, 14, 23, 0.5)';
    inputDiv.style.padding = '15px';
    inputDiv.style.borderRadius = '10px';
    inputDiv.style.marginBottom = '10px';
    inputDiv.innerHTML = `
        <h4 style="color: var(--light-blue); margin-bottom: 10px;">Analyzed Pattern:</h4>
        <p><strong>Pattern:</strong> ${inputFields.pattern || 'Not provided'}</p>
        <p><strong>Function:</strong> ${inputFields.function || 'Not provided'}</p>
        <p><strong>Hash:</strong> ${inputFields.hashPattern || 'Not provided'}</p>
    `;
    matchDetails.appendChild(inputDiv);
    
    // Show best match details
    const matchDiv = document.createElement('div');
    matchDiv.style.gridColumn = 'span 3';
    matchDiv.innerHTML = `<h4 style="color: var(--light-blue); margin: 10px 0;">Best Match: ${bestMatch.detection.name}</h4>`;
    matchDetails.appendChild(matchDiv);
    
    // Pattern match
    const patternItem = document.createElement('div');
    patternItem.className = `match-item ${bestMatch.matches.pattern >= 70 ? 'matched' : (bestMatch.matches.pattern >= 30 ? 'partial' : '')}`;
    patternItem.innerHTML = `
        <h4>Pattern Match</h4>
        <div class="match-value">${bestMatch.matches.pattern}%</div>
        <div>Expected: ${bestMatch.detection.pattern.substring(0, 30)}${bestMatch.detection.pattern.length > 30 ? '...' : ''}</div>
        <div class="match-score">Score: ${Math.round(bestMatch.matches.pattern * bestMatch.detection.weight.pattern / 100)}/${bestMatch.detection.weight.pattern}</div>
    `;
    matchDetails.appendChild(patternItem);
    
    // Function match
    const functionItem = document.createElement('div');
    functionItem.className = `match-item ${bestMatch.matches.function >= 70 ? 'matched' : (bestMatch.matches.function >= 30 ? 'partial' : '')}`;
    functionItem.innerHTML = `
        <h4>Function Match</h4>
        <div class="match-value">${bestMatch.matches.function}%</div>
        <div>Expected: ${bestMatch.detection.function}</div>
        <div class="match-score">Score: ${Math.round(bestMatch.matches.function * bestMatch.detection.weight.function / 100)}/${bestMatch.detection.weight.function}</div>
    `;
    matchDetails.appendChild(functionItem);
    
    // Hash match
    const hashItem = document.createElement('div');
    hashItem.className = `match-item ${bestMatch.matches.hash >= 70 ? 'matched' : (bestMatch.matches.hash >= 30 ? 'partial' : '')}`;
    hashItem.innerHTML = `
        <h4>Hash Match</h4>
        <div class="match-value">${bestMatch.matches.hash}%</div>
        <div>Expected: ${bestMatch.detection.hashPattern.substring(0, 20)}...</div>
        <div class="match-score">Score: ${Math.round(bestMatch.matches.hash * bestMatch.detection.weight.hash / 100)}/${bestMatch.detection.weight.hash}</div>
    `;
    matchDetails.appendChild(hashItem);
    
    // Show other potential matches
    if (results.length > 1 && results[1].totalScore > 0) {
        const otherMatches = document.createElement('div');
        otherMatches.style.gridColumn = 'span 3';
        otherMatches.style.marginTop = '15px';
        otherMatches.innerHTML = '<h4 style="color: var(--light-blue);">Other Potential Matches:</h4>';
        
        for (let i = 1; i < Math.min(3, results.length); i++) {
            if (results[i].totalScore > 0) {
                otherMatches.innerHTML += `
                    <div style="background: rgba(10, 14, 23, 0.5); padding: 10px; border-radius: 5px; margin-top: 5px;">
                        <strong>${results[i].detection.name}:</strong> ${results[i].totalScore}% match
                    </div>
                `;
            }
        }
        
        matchDetails.appendChild(otherMatches);
    }
    
    // Set verdict
    const severityClass = getSeverityClass(bestMatch.totalScore, bestMatch.severity);
    let verdictText = '';
    
    if (bestMatch.totalScore >= 70) {
        verdictText = `⚠️ HIGH CONFIDENCE MATCH - ${bestMatch.detection.name}`;
    } else if (bestMatch.totalScore >= 30) {
        verdictText = `⚠️ SUSPICIOUS - Partial match with ${bestMatch.detection.name}`;
    } else {
        verdictText = '✓ CLEAN - No significant matches found';
    }
    
    verdictBox.innerHTML = `<span class="status ${severityClass}">${verdictText}</span>`;
    
    detectionStatus.style.display = 'block';
}

// Export functions for use in main.js if needed
window.analyzeDetection = analyzeDetection;
window.extractDetectionFields = extractDetectionFields;
