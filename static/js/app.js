// ============================================================================
// DEEP LEARNING IDS - FRONTEND APPLICATION
// ============================================================================

const API_URL = 'http://localhost:5001';

// ============================================================================
// FORM SUBMISSION
// ============================================================================

document.getElementById('detectionForm').addEventListener('submit', async (e) => {
    e.preventDefault();

    const formData = new FormData(e.target);
    const data = {};

    // Convert form data to object
    for (let [key, value] of formData.entries()) {
        // Convert numeric fields
        if (['duration', 'src_bytes', 'dst_bytes', 'logged_in', 'num_failed_logins',
            'num_compromised', 'root_shell', 'su_attempted', 'num_root',
            'count', 'srv_count', 'serror_rate', 'srv_serror_rate'].includes(key)) {
            data[key] = parseFloat(value) || 0;
        } else {
            data[key] = value;
        }
    }

    // Add remaining required fields with default values
    const defaultFields = {
        land: 0, wrong_fragment: 0, urgent: 0, hot: 0,
        num_file_creations: 0, num_shells: 0, num_access_files: 0,
        num_outbound_cmds: 0, is_host_login: 0, is_guest_login: 0,
        rerror_rate: 0, srv_rerror_rate: 0, same_srv_rate: 0,
        diff_srv_rate: 0, srv_diff_host_rate: 0, dst_host_count: 0,
        dst_host_srv_count: 0, dst_host_same_srv_rate: 0,
        dst_host_diff_srv_rate: 0, dst_host_same_src_port_rate: 0,
        dst_host_srv_diff_host_rate: 0, dst_host_serror_rate: 0,
        dst_host_srv_serror_rate: 0, dst_host_rerror_rate: 0,
        dst_host_srv_rerror_rate: 0
    };

    Object.keys(defaultFields).forEach(key => {
        if (!(key in data)) {
            data[key] = defaultFields[key];
        }
    });

    // Show loading state
    const detectBtn = document.getElementById('detectBtn');
    const btnText = detectBtn.querySelector('.btn-text');
    const btnLoader = detectBtn.querySelector('.btn-loader');

    detectBtn.disabled = true;
    btnText.style.display = 'none';
    btnLoader.style.display = 'inline-block';

    try {
        const response = await fetch(`${API_URL}/predict`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(data)
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const result = await response.json();
        displayResults(result);

    } catch (error) {
        console.error('Error:', error);
        alert(`Error: ${error.message}\n\nMake sure the Flask server is running on ${API_URL}`);
    } finally {
        detectBtn.disabled = false;
        btnText.style.display = 'inline';
        btnLoader.style.display = 'none';
    }
});

// ============================================================================
// DISPLAY RESULTS
// ============================================================================

function displayResults(result) {
    const resultsCard = document.getElementById('resultsCard');
    resultsCard.style.display = 'block';

    // Update threat info
    document.getElementById('resultThreat').textContent = result.attack_type;
    document.getElementById('resultSeverity').textContent = result.severity;
    document.getElementById('resultConfidence').textContent =
        `${(result.confidence * 100).toFixed(1)}%`;

    // Update threat icon
    const threatIcon = document.getElementById('threatIcon');
    threatIcon.className = 'threat-icon';

    const severityClass = result.severity.toLowerCase();
    threatIcon.classList.add(severityClass);

    // Update severity badge
    const severityBadge = document.getElementById('resultSeverity');
    severityBadge.className = `result-severity ${severityClass}`;

    // Update description and recommendations
    document.getElementById('threatDescription').textContent =
        result.threat_description;

    const recommendationsList = document.getElementById('recommendations');
    recommendationsList.innerHTML = '';
    result.recommendations.forEach(rec => {
        const li = document.createElement('li');
        li.textContent = rec;
        recommendationsList.appendChild(li);
    });

    // Update probability bars
    displayProbabilities(result.probabilities);

    // Update metadata
    document.getElementById('modelUsed').textContent = result.model_used;
    document.getElementById('timestamp').textContent =
        new Date(result.timestamp).toLocaleString();

    // Smooth scroll to results
    resultsCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function displayProbabilities(probabilities) {
    const container = document.getElementById('probabilityBars');
    container.innerHTML = '';

    // Sort by probability (highest first)
    const sorted = Object.entries(probabilities)
        .sort((a, b) => b[1] - a[1]);

    sorted.forEach(([label, value]) => {
        const barDiv = document.createElement('div');
        barDiv.className = 'probability-bar';

        barDiv.innerHTML = `
            <span class="probability-label">${label}</span>
            <div class="probability-track">
                <div class="probability-fill" style="width: ${value * 100}%"></div>
            </div>
            <span class="probability-value">${(value * 100).toFixed(1)}%</span>
        `;

        container.appendChild(barDiv);
    });
}

// ============================================================================
// QUICK FILL FUNCTIONS
// ============================================================================

function fillNormal() {
    document.getElementById('duration').value = 0;
    document.getElementById('protocol_type').value = 'tcp';
    document.getElementById('service').value = 'http';
    document.getElementById('flag').value = 'SF';
    document.getElementById('src_bytes').value = 181;
    document.getElementById('dst_bytes').value = 5450;
    document.getElementById('logged_in').value = 1;
    document.getElementById('num_failed_logins').value = 0;
    document.getElementById('num_compromised').value = 0;
    document.getElementById('root_shell').value = 0;
    document.getElementById('su_attempted').value = 0;
    document.getElementById('num_root').value = 0;
    document.getElementById('count').value = 8;
    document.getElementById('srv_count').value = 8;
    document.getElementById('serror_rate').value = 0;
    document.getElementById('srv_serror_rate').value = 0;
}

function fillDoS() {
    document.getElementById('duration').value = 0;
    document.getElementById('protocol_type').value = 'icmp';
    document.getElementById('service').value = 'other';
    document.getElementById('flag').value = 'SF';
    document.getElementById('src_bytes').value = 1032;
    document.getElementById('dst_bytes').value = 0;
    document.getElementById('logged_in').value = 0;
    document.getElementById('num_failed_logins').value = 0;
    document.getElementById('num_compromised').value = 0;
    document.getElementById('root_shell').value = 0;
    document.getElementById('su_attempted').value = 0;
    document.getElementById('num_root').value = 0;
    document.getElementById('count').value = 511;
    document.getElementById('srv_count').value = 511;
    document.getElementById('serror_rate').value = 0;
    document.getElementById('srv_serror_rate').value = 0;
}

function fillR2L() {
    document.getElementById('duration').value = 0;
    document.getElementById('protocol_type').value = 'tcp';
    document.getElementById('service').value = 'ftp';
    document.getElementById('flag').value = 'SF';
    document.getElementById('src_bytes').value = 0;
    document.getElementById('dst_bytes').value = 0;
    document.getElementById('logged_in').value = 0;
    document.getElementById('num_failed_logins').value = 3;
    document.getElementById('num_compromised').value = 1;
    document.getElementById('root_shell').value = 0;
    document.getElementById('su_attempted').value = 1;
    document.getElementById('num_root').value = 0;
    document.getElementById('count').value = 1;
    document.getElementById('srv_count').value = 2;
    document.getElementById('serror_rate').value = 0;
    document.getElementById('srv_serror_rate').value = 0.5;
}
function fillProbe() {
    // Probe-type (scanning / reconnaissance) example values
    document.getElementById('duration').value = 1;
    document.getElementById('protocol_type').value = 'icmp';   // probes often use ICMP/UDP/TCP
    document.getElementById('service').value = 'eco_i';        // ICMP echo
    document.getElementById('flag').value = 'SF';
    document.getElementById('src_bytes').value = 0;
    document.getElementById('dst_bytes').value = 0;
    document.getElementById('logged_in').value = 0;
    document.getElementById('num_failed_logins').value = 0;
    document.getElementById('num_compromised').value = 0;
    document.getElementById('root_shell').value = 0;
    document.getElementById('su_attempted').value = 0;
    document.getElementById('num_root').value = 0;
    document.getElementById('count').value = 100;        // many hosts/attempts in scans
    document.getElementById('srv_count').value = 80;     // many services targeted
    document.getElementById('serror_rate').value = 0;
    document.getElementById('srv_serror_rate').value = 0;
    
}
function fillU2R() {
    // U2R-type (user-to-root privilege escalation) example values
    document.getElementById('duration').value = 0;
    document.getElementById('protocol_type').value = 'tcp';
    document.getElementById('service').value = 'telnet';   // often interactive services
    document.getElementById('flag').value = 'SF';
    document.getElementById('src_bytes').value = 120;
    document.getElementById('dst_bytes').value = 240;
    document.getElementById('logged_in').value = 1;        // attacker had a user session
    document.getElementById('num_failed_logins').value = 0;
    document.getElementById('num_compromised').value = 0;
    document.getElementById('root_shell').value = 1;       // escalated to root
    document.getElementById('su_attempted').value = 1;     // attempted privilege escalation
    document.getElementById('num_root').value = 1;
    document.getElementById('count').value = 1;            // single, targeted action
    document.getElementById('srv_count').value = 1;
    document.getElementById('serror_rate').value = 0;
    document.getElementById('srv_serror_rate').value = 0;
}


// ============================================================================
// CSV UPLOAD
// ============================================================================

document.getElementById('csvFile').addEventListener('change', async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    const formData = new FormData();
    formData.append('file', file);

    try {
        const response = await fetch(`${API_URL}/upload`, {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const result = await response.json();
        displayBatchResults(result);

    } catch (error) {
        console.error('Error:', error);
        alert(`Error uploading file: ${error.message}`);
    }
});

function displayBatchResults(result) {
    const batchResults = document.getElementById('batchResults');
    batchResults.style.display = 'block';

    const summary = result.summary;
    const distribution = summary.attack_distribution;

    // Create summary cards
    const summaryDiv = document.getElementById('batchSummary');
    summaryDiv.innerHTML = `
        <div class="summary-card">
            <div class="summary-value">${summary.total_samples}</div>
            <div class="summary-label">Total Samples</div>
        </div>
    `;

    // Add cards for each attack type
    Object.entries(distribution).forEach(([type, count]) => {
        const percentage = ((count / summary.total_samples) * 100).toFixed(1);
        summaryDiv.innerHTML += `
            <div class="summary-card">
                <div class="summary-value">${count}</div>
                <div class="summary-label">${type} (${percentage}%)</div>
            </div>
        `;
    });

    // Create simple bar chart
    const chartDiv = document.getElementById('batchChart');
    chartDiv.innerHTML = '<h4 style="margin-bottom: 1rem;">Attack Distribution</h4>';

    Object.entries(distribution).forEach(([type, count]) => {
        const percentage = (count / summary.total_samples) * 100;
        chartDiv.innerHTML += `
            <div class="probability-bar">
                <span class="probability-label">${type}</span>
                <div class="probability-track">
                    <div class="probability-fill" style="width: ${percentage}%"></div>
                </div>
                <span class="probability-value">${count}</span>
            </div>
        `;
    });

    batchResults.scrollIntoView({ behavior: 'smooth' });
}

// ============================================================================
// DRAG AND DROP
// ============================================================================

const uploadZone = document.getElementById('uploadZone');

uploadZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    uploadZone.style.borderColor = 'var(--primary)';
    uploadZone.style.background = 'rgba(99, 102, 241, 0.05)';
});

uploadZone.addEventListener('dragleave', (e) => {
    e.preventDefault();
    uploadZone.style.borderColor = 'var(--border)';
    uploadZone.style.background = '';
});

uploadZone.addEventListener('drop', (e) => {
    e.preventDefault();
    uploadZone.style.borderColor = 'var(--border)';
    uploadZone.style.background = '';

    const file = e.dataTransfer.files[0];
    if (file && file.name.endsWith('.csv')) {
        document.getElementById('csvFile').files = e.dataTransfer.files;
        document.getElementById('csvFile').dispatchEvent(new Event('change'));
    } else {
        alert('Please upload a CSV file');
    }
});

// ============================================================================
// SMOOTH SCROLLING
// ============================================================================

document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({
                behavior: 'smooth',
                block: 'start'
            });
        }
    });
});

// ============================================================================
// INITIALIZATION
// ============================================================================

// Check API health on load
window.addEventListener('load', async () => {
    try {
        const response = await fetch(`${API_URL}/health`);
        const data = await response.json();

        if (data.models_loaded) {
            console.log('✅ API is healthy and models are loaded');
        } else {
            console.warn('⚠️ API is up but models are not loaded');
        }
    } catch (error) {
        console.error('❌ Cannot connect to API:', error);
        console.log(`Make sure Flask server is running on ${API_URL}`);
    }
});