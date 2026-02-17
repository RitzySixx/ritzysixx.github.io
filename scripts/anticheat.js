// Anticheat Detection Patterns Database
const cheatDetections = [
    {
        name: "Generic Menu PTFX Detection",
        description: "Common menu-based cheat using particle effects",
        fields: {
            pattern: "@monitor/resource/menu/client/cl_ptfx.lua:CreatePlayerModePtfxLoop:84:85:116",
            function: "CreateThread",
            hashPattern: "6387d32971b38551c3e994b111ba6787"
        },
        severity: "danger"
    },
    {
        name: "Invisible Method #1",
        description: "Outfit manipulation cheat using SetEntityVisible",
        fields: {
            pattern: "@monitor/outfits.lua:fn:97:120:121",
            function: "SetEntityVisible",
            hashPattern: "02ce22e210fa749a671171010f05dd7e"
        },
        severity: "danger"
    },
    {
        name: "Generic Noclip #1",
        description: "Noclip detection based on invalid player speed",
        fields: {
            dbg: "5.8626070022583/7.6397044767891/1.7770974745308",
            reason: "Invalid Player Speed"
        },
        severity: "danger"
    },
    {
        name: "RPG Detection",
        description: "Blacklisted projectile detected (RPG)",
        fields: {
            reason: "Blacklisted Projectile Detected",
            weapon: "WEAPON_RPG"
        },
        severity: "danger"
    },
    {
        name: "FreeCam Detection #1",
        description: "FreeCam detection with multiple indicators",
        fields: {
            reason: "FreeCam Detected",
            distance: "3.9234402179718",
            detection: "Type #3",
            maxVertical: "1.34515040297831",
            verticalDot: "3.6654414030109",
            horizontalDot: "1.03867003418417",
            maxHorizontal: "0.40034238183878"
        },
        severity: "danger"
    }
];

// Function to extract all labeled fields from pasted input
function extractFields(input) {
    const lines = input.split('\n').filter(line => line.trim() !== '');
    const fields = {};          // key -> value for labeled lines
    const other = [];            // unlabeled lines

    for (let line of lines) {
        line = line.trim();
        const colonIndex = line.indexOf(':');
        if (colonIndex > 0) {
            const key = line.substring(0, colonIndex).trim().toLowerCase();
            const value = line.substring(colonIndex + 1).trim();
            // Store with original casing? We'll keep value as is, key lowercased for matching.
            fields[key] = value;
        } else {
            other.push(line);
        }
    }
    return { fields, other };
}

// Function to match detection against known patterns
function matchDetection(inputFields, otherLines) {
    const results = [];

    for (const detection of cheatDetections) {
        const expectedFields = detection.fields;
        const expectedKeys = Object.keys(expectedFields);
        let matchedCount = 0;

        // For each expected key, check if input has it and value matches
        for (const key of expectedKeys) {
            // Try to match from labeled fields first (case-insensitive key)
            if (inputFields[key] !== undefined && inputFields[key] === expectedFields[key]) {
                matchedCount++;
            }
            // Also check if the value appears in unlabeled lines (for pastes without labels)
            else if (otherLines.includes(expectedFields[key])) {
                matchedCount++;
            }
        }

        const totalPossible = expectedKeys.length;
        const percentage = totalPossible > 0 ? Math.round((matchedCount / totalPossible) * 100) : 0;

        // Build match details for each expected field
        const matches = {};
        for (const key of expectedKeys) {
            const inputVal = inputFields[key];
            const expectedVal = expectedFields[key];
            matches[key] = (inputVal !== undefined && inputVal === expectedVal) || otherLines.includes(expectedVal);
        }

        results.push({
            detection: detection,
            matches: matches,
            matchedFields: matchedCount,
            totalPossibleFields: totalPossible,
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

        // Create a short preview of fields
        const fieldPreview = Object.entries(detection.fields)
            .map(([k, v]) => `${k}: ${v.substring(0, 20)}${v.length > 20 ? '...' : ''}`)
            .join('<br>');

        item.innerHTML = `
            <h4>${detection.name}</h4>
            <p>${detection.description}</p>
            <small>${fieldPreview}</small>
            <br>
            <small>Severity: <span class="status ${detection.severity}">${detection.severity}</span></small>
        `;

        // Add click handler to fill textarea with this detection
        item.addEventListener('click', () => {
            const textarea = document.getElementById('detectionInput');
            if (textarea) {
                // Build a string with all fields
                const lines = Object.entries(detection.fields)
                    .map(([k, v]) => `${k}:\n${v}`);
                textarea.value = lines.join('\n\n');
            }
        });

        grid.appendChild(item);
    });
}

// Function to display analysis results
function displayResults(inputFields, otherLines, results) {
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

    // Show input fields
    const inputDiv = document.createElement('div');
    inputDiv.style.gridColumn = 'span 3';
    inputDiv.style.background = 'rgba(10, 14, 23, 0.5)';
    inputDiv.style.padding = '15px';
    inputDiv.style.borderRadius = '10px';
    inputDiv.style.marginBottom = '10px';

    let inputHtml = '<h4 style="color: var(--light-blue); margin-bottom: 10px;">Analyzed Input:</h4>';
    for (const [key, value] of Object.entries(inputFields)) {
        inputHtml += `<p><strong>${key}:</strong> ${value}</p>`;
    }
    if (otherLines.length > 0) {
        otherLines.forEach((val, i) => {
            inputHtml += `<p><strong>String ${i+1}:</strong> ${val}</p>`;
        });
    }

    inputDiv.innerHTML = inputHtml;
    matchDetails.appendChild(inputDiv);

    // Show best match details
    const matchDiv = document.createElement('div');
    matchDiv.style.gridColumn = 'span 3';
    matchDiv.innerHTML = `<h4 style="color: var(--light-blue); margin: 10px 0;">Best Match: ${bestMatch.detection.name}</h4>`;
    matchDetails.appendChild(matchDiv);

    // Display each field of the detection and whether it matched
    const expectedFields = bestMatch.detection.fields;
    for (const [key, expectedValue] of Object.entries(expectedFields)) {
        const matched = bestMatch.matches[key];
        const item = document.createElement('div');
        item.className = `match-item ${matched ? 'matched' : ''}`;
        item.innerHTML = `
            <h4>${key}</h4>
            <div class="match-value">${matched ? '✓ MATCHED' : '✗ NO MATCH'}</div>
            <div>Expected: ${expectedValue}</div>
        `;
        matchDetails.appendChild(item);
    }

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
                    <strong>${match.detection.name}:</strong> ${match.totalScore}% (${match.matchedFields}/${match.totalPossibleFields} fields matched)
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
        verdictText = `⚠️ PARTIAL MATCH - ${bestMatch.matchedFields}/${bestMatch.totalPossibleFields} fields matched with ${bestMatch.detection.name}`;
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

            const { fields, other } = extractFields(input);
            const results = matchDetection(fields, other);

            displayResults(fields, other, results);
        });
    }

    if (clearBtn) {
        clearBtn.addEventListener('click', function() {
            detectionInput.value = '';
            document.getElementById('detectionStatus').style.display = 'none';
        });
    }
});
