/**
 * AEGIS PORT SCANNER — DUAL-THEME WORKSTATION CONTROLLER
 */

document.addEventListener('DOMContentLoaded', () => {
    // =========================================================================
    // THEME MANAGEMENT (DARK / LIGHT / SYSTEM)
    // =========================================================================
    const themeMenuBtn = document.getElementById('theme-menu-btn');
    const themeDropdownMenu = document.getElementById('theme-dropdown-menu');
    const themeActiveIcon = document.getElementById('theme-active-icon');
    const themeRadioInputs = document.querySelectorAll('input[name="appearance-theme-opt"]');

    // Load persisted theme
    const savedTheme = localStorage.getItem('aegis-theme') || 'system';
    applyTheme(savedTheme);

    // Header theme menu button handler
    if (themeMenuBtn) {
        themeMenuBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            themeDropdownMenu.classList.toggle('hidden');
        });
    }

    // Close dropdown when clicking outside
    document.addEventListener('click', () => {
        if (themeDropdownMenu) {
            themeDropdownMenu.classList.add('hidden');
        }
    });

    // Dropdown items click listeners
    const dropdownOptions = themeDropdownMenu ? themeDropdownMenu.querySelectorAll('[data-theme]') : [];
    dropdownOptions.forEach(opt => {
        opt.addEventListener('click', () => {
            const chosen = opt.getAttribute('data-theme');
            applyTheme(chosen);
            showToast(`Theme changed to ${chosen.toUpperCase()}`, 'info');
        });
    });

    // Settings radio inputs change listeners
    themeRadioInputs.forEach(input => {
        input.addEventListener('change', () => {
            if (input.checked) {
                applyTheme(input.value);
                showToast(`Theme preference updated to ${input.value.toUpperCase()}`, 'info');
            }
        });
    });

    // Listen for system theme preference changes
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
        if (localStorage.getItem('aegis-theme') === 'system' || !localStorage.getItem('aegis-theme')) {
            applyTheme('system');
        }
    });

    function applyTheme(theme) {
        localStorage.setItem('aegis-theme', theme);
        const resolvedTheme = resolveThemeName(theme);

        // Apply HTML tags
        if (resolvedTheme === 'dark') {
            document.documentElement.classList.add('dark');
            document.documentElement.classList.remove('light');
            if (themeActiveIcon) themeActiveIcon.textContent = 'dark_mode';
        } else {
            document.documentElement.classList.add('light');
            document.documentElement.classList.remove('dark');
            if (themeActiveIcon) themeActiveIcon.textContent = 'light_mode';
        }

        // Sync settings radio buttons
        themeRadioInputs.forEach(input => {
            input.checked = (input.value === theme);
        });
    }

    function resolveThemeName(theme) {
        if (theme === 'system') {
            return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
        }
        return theme;
    }

    // =========================================================================
    // WORKSPACE NAVIGATION / TABS
    // =========================================================================
    const navLinks = {
        dashboard: document.getElementById('nav-link-dashboard'),
        newScan: document.getElementById('nav-link-new-scan'),
        history: document.getElementById('nav-link-history'),
        compare: document.getElementById('nav-link-compare'),
        reports: document.getElementById('nav-link-reports'),
        settings: document.getElementById('nav-link-settings'),
        copilot: document.getElementById('nav-link-copilot')
    };

    const views = {
        dashboard: document.getElementById('view-dashboard'),
        newScan: document.getElementById('view-new-scan'),
        results: document.getElementById('view-scan-results'),
        history: document.getElementById('view-history'),
        compare: document.getElementById('view-compare'),
        reports: document.getElementById('view-reports'),
        settings: document.getElementById('view-settings'),
        copilot: document.getElementById('view-copilot')
    };

    const sidebarInitiateScan = document.getElementById('sidebar-initiate-scan');
    const headerSettingsBtn = document.getElementById('header-settings-btn');
    const viewAllLogsBtn = document.getElementById('view-all-logs-btn');
    const historyCompareBtn = document.getElementById('history-compare-btn');

    // Sidebar navigation trigger
    Object.keys(navLinks).forEach(key => {
        if (navLinks[key]) {
            navLinks[key].addEventListener('click', (e) => {
                e.preventDefault();
                switchView(key);
            });
        }
    });

    if (sidebarInitiateScan) {
        sidebarInitiateScan.addEventListener('click', () => {
            switchView('newScan');
            targetInput.focus();
        });
    }

    if (headerSettingsBtn) {
        headerSettingsBtn.addEventListener('click', () => switchView('settings'));
    }

    if (viewAllLogsBtn) {
        viewAllLogsBtn.addEventListener('click', () => switchView('history'));
    }

    if (historyCompareBtn) {
        historyCompareBtn.addEventListener('click', () => switchView('compare'));
    }

    function switchView(viewName) {
        // Hide all views
        Object.keys(views).forEach(k => {
            if (views[k]) views[k].classList.add('hidden');
        });
        
        // Show target view
        if (views[viewName]) {
            views[viewName].classList.remove('hidden');
        }

        // Update active nav button styles
        Object.keys(navLinks).forEach(k => {
            if (navLinks[k]) {
                if (k === 'copilot') {
                    if (viewName === 'copilot') {
                        navLinks[k].className = 'w-full flex items-center gap-3 px-3 py-2.5 rounded bg-secondary-container border border-primary text-on-secondary-container transition-all cursor-pointer group shadow-sm';
                    } else {
                        navLinks[k].className = 'w-full flex items-center gap-3 px-3 py-2.5 rounded bg-surface-container hover:bg-surface-container-highest border border-primary/30 text-on-surface transition-all cursor-pointer group';
                    }
                } else {
                    if (k === viewName) {
                        navLinks[k].className = 'w-full flex items-center gap-3 px-4 py-2 border-l-2 border-primary bg-secondary-container text-on-secondary-container transition-all';
                    } else {
                        navLinks[k].className = 'w-full flex items-center gap-3 px-4 py-2 text-on-surface-variant hover:bg-surface-container-highest transition-colors';
                    }
                }
            }
        });

        // Trigger automatic loads
        if (viewName === 'dashboard' || viewName === 'history' || viewName === 'reports') {
            loadDashboardData();
        }
        if (viewName === 'compare') {
            loadCompareOptions();
        }
        if (viewName === 'copilot') {
            const copilotInput = document.getElementById('copilot-input-text');
            if (copilotInput) {
                setTimeout(() => copilotInput.focus(), 50);
            }
        }
    }

    // =========================================================================
    // DOM ELEMENTS - CORE ACTIONS
    // =========================================================================
    const scanForm = document.getElementById('scan-form');
    const quickScanForm = document.getElementById('quick-scan-form');
    
    const targetInput = document.getElementById('target-input');
    const quickTargetInput = document.getElementById('quick-target-input');
    
    const startScanBtn = document.getElementById('start-scan-btn');
    const btnText = document.getElementById('btn-text');
    const btnSpinner = document.getElementById('btn-spinner');
    const scanStatusBadge = document.getElementById('scan-status-badge');
    
    const errorContainer = document.getElementById('error-container');
    const errorMessage = document.getElementById('error-message');
    const loadingContainer = document.getElementById('loading-container');

    const resultTargetIp = document.getElementById('result-target-ip');
    const resultProfile = document.getElementById('result-profile');
    const resultPortsCount = document.getElementById('result-ports-count');
    const resultOverallRisk = document.getElementById('result-overall-risk');
    const resultStatus = document.getElementById('result-status');
    const resultBreakdownText = document.getElementById('result-breakdown-text');
    const resultsTableWrapper = document.getElementById('results-table-wrapper');
    const resultsTableBody = document.getElementById('results-table-body');
    const emptyPortsMessage = document.getElementById('empty-ports-message');
    const exportReportLink = document.getElementById('export-report-link');
    const exportReportPdfLink = document.getElementById('export-report-pdf-link');
    const exportReportCsvLink = document.getElementById('export-report-csv-link');
    const exportReportJsonLink = document.getElementById('export-report-json-link');
    const remediationPlaybookSection = document.getElementById('remediation-playbook-section');
    const remediationCardsContainer = document.getElementById('remediation-cards-container');
    const remediationEmptyMessage = document.getElementById('remediation-empty-message');
    const resultScoreNum = document.getElementById('result-score-num');
    const resultScoreLabel = document.getElementById('result-score-label');
    const securityScoreWidget = document.getElementById('security-score-widget');
    const scoreBandBadge = document.getElementById('score-band-badge');
    const scoreDisplayNum = document.getElementById('score-display-num');
    const scoreMeterFill = document.getElementById('score-meter-fill');
    const scoreTotalDeductions = document.getElementById('score-total-deductions');
    const scoreDeductionsList = document.getElementById('score-deductions-list');
    const serviceFingerprintsSection = document.getElementById('service-fingerprints-section');
    const fingerprintsCardsContainer = document.getElementById('fingerprints-cards-container');
    const fingerprintsEmptyMessage = document.getElementById('fingerprints-empty-message');

    const historyTableWrapper = document.getElementById('history-table-wrapper');
    const historyTableBody = document.getElementById('history-table-body');
    const emptyHistoryBox = document.getElementById('empty-history-box');
    const clearHistoryBtn = document.getElementById('clear-history-btn');

    const confirmModal = document.getElementById('confirm-modal');
    const modalCancelBtn = document.getElementById('modal-cancel-btn');
    const modalConfirmBtn = document.getElementById('modal-confirm-btn');
    const toastContainer = document.getElementById('toast-container');

    // AI Security Analyst elements
    const aiAnalystContainer = document.getElementById('ai-analyst-container');
    const generateAiBtn = document.getElementById('generate-ai-btn');
    const generateAiBtnText = document.getElementById('generate-ai-btn-text');
    const generateAiBtnIcon = document.getElementById('generate-ai-btn-icon');
    const generateAiSpinner = document.getElementById('generate-ai-spinner');
    const aiBadgeStatus = document.getElementById('ai-badge-status');
    const aiStatusMessage = document.getElementById('ai-status-message');
    const aiAssessmentResults = document.getElementById('ai-assessment-results');
    const aiSummaryText = document.getElementById('ai-summary-text');
    const aiFindingsList = document.getElementById('ai-findings-list');
    const aiRecommendationsList = document.getElementById('ai-recommendations-list');
    const aiBeginnerText = document.getElementById('ai-beginner-text');
    const aiVerificationList = document.getElementById('ai-verification-list');
    const aiModelMeta = document.getElementById('ai-model-meta');
    let currentScanId = null;

    // Scan Comparison elements
    const compareBaseSelect = document.getElementById('compare-base-select');
    const compareTargetSelect = document.getElementById('compare-target-select');
    const executeCompareBtn = document.getElementById('execute-compare-btn');
    const compareBtnText = document.getElementById('compare-btn-text');
    const compareBtnIcon = document.getElementById('compare-btn-icon');
    const compareBtnSpinner = document.getElementById('compare-btn-spinner');
    const compareStatusBadge = document.getElementById('compare-status-badge');
    const compareErrorContainer = document.getElementById('compare-error-container');
    const compareErrorMessage = document.getElementById('compare-error-message');
    const compareLoadingContainer = document.getElementById('compare-loading-container');
    const compareEmptyState = document.getElementById('compare-empty-state');
    const compareResultsContainer = document.getElementById('compare-results-container');
    const compareTargetName = document.getElementById('compare-target-name');
    const compareSummaryText = document.getElementById('compare-summary-text');
    const compareEarlierId = document.getElementById('compare-earlier-id');
    const compareEarlierTime = document.getElementById('compare-earlier-time');
    const compareEarlierProfile = document.getElementById('compare-earlier-profile');
    const compareEarlierPorts = document.getElementById('compare-earlier-ports');
    const compareEarlierScore = document.getElementById('compare-earlier-score');
    const compareLaterId = document.getElementById('compare-later-id');
    const compareLaterTime = document.getElementById('compare-later-time');
    const compareLaterProfile = document.getElementById('compare-later-profile');
    const compareLaterPorts = document.getElementById('compare-later-ports');
    const compareLaterScore = document.getElementById('compare-later-score');
    const compareScoreDeltaBanner = document.getElementById('compare-score-delta-banner');
    const compareScoreDeltaVal = document.getElementById('compare-score-delta-val');
    const compareScoreDeltaInterpretation = document.getElementById('compare-score-delta-interpretation');
    const compareProfileWarning = document.getElementById('compare-profile-warning');
    const compareProfileWarningText = document.getElementById('compare-profile-warning-text');
    const compareCountNew = document.getElementById('compare-count-new');
    const compareCountMissing = document.getElementById('compare-count-missing');
    const compareCountChanged = document.getElementById('compare-count-changed');
    const compareCountUnchanged = document.getElementById('compare-count-unchanged');
    const compareNewPortsList = document.getElementById('compare-new-ports-list');
    const compareMissingPortsList = document.getElementById('compare-missing-ports-list');
    const compareChangedPortsList = document.getElementById('compare-changed-ports-list');
    const compareUnchangedPortsList = document.getElementById('compare-unchanged-ports-list');
    const compareCaveatsText = document.getElementById('compare-caveats-text');

    const quickTags = document.querySelectorAll('.quick-tag');
    const recommendScanBtn = document.getElementById('recommend-scan-btn');
    const scanNeedInput = document.getElementById('scan-need-input');
    const recommendationPanel = document.getElementById('scan-recommendation');
    const useRecommendedProfileBtn = document.getElementById('use-recommended-profile');
    const selectedProfileLabel = document.getElementById('selected-profile-label');
    let selectedScanProfile = {
        profile_id: 'quick',
        name: 'Quick scan',
        flags: '-sT -F'
    };
    let currentRecommendation = null;

    if (recommendScanBtn) {
        recommendScanBtn.addEventListener('click', async () => {
            const need = scanNeedInput.value.trim();
            if (!need) {
                showError('Describe what you need to check before asking for a recommendation.');
                return;
            }

            hideElement(errorContainer);
            recommendScanBtn.disabled = true;
            recommendScanBtn.textContent = 'Thinking...';
            try {
                const response = await fetch('/api/assistant/recommend', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ need })
                });
                const data = await response.json();
                if (!response.ok || data.status !== 'success') {
                    showError(data.message || 'The assistant could not make a recommendation.');
                    return;
                }

                currentRecommendation = data.recommendation;
                document.getElementById('scan-recommendation-name').textContent = currentRecommendation.name;
                document.getElementById('scan-recommendation-flags').textContent = `Nmap flags: ${currentRecommendation.flags}`;
                document.getElementById('scan-recommendation-description').textContent = currentRecommendation.description;
                document.getElementById('scan-recommendation-explanation').textContent = currentRecommendation.explanation;
                document.getElementById('scan-recommendation-caution').textContent = currentRecommendation.caution;
                showElement(recommendationPanel);
            } catch (_) {
                showError('Could not connect to the AI assistant. Check that the Flask server is running.');
            } finally {
                recommendScanBtn.disabled = false;
                recommendScanBtn.textContent = 'Recommend flags';
            }
        });
    }

    if (useRecommendedProfileBtn) {
        useRecommendedProfileBtn.addEventListener('click', () => {
            if (!currentRecommendation) return;
            selectedScanProfile = currentRecommendation;
            selectedProfileLabel.textContent = `Selected profile: ${selectedScanProfile.name} (${selectedScanProfile.flags})`;
            showToast('Recommended scan profile selected. Review the target, then start the scan.', 'success');
        });
    }

    // Binds target clicks
    quickTags.forEach(tag => {
        tag.addEventListener('click', () => {
            const val = tag.getAttribute('data-target');
            if (val) {
                targetInput.value = val;
                targetInput.focus();
            }
        });
    });

    // =========================================================================
    // SCANNER LOGIC
    // =========================================================================
    if (scanForm) {
        scanForm.addEventListener('submit', (e) => {
            e.preventDefault();
            executeScan(targetInput.value.trim());
        });
    }

    if (quickScanForm) {
        quickScanForm.addEventListener('submit', (e) => {
            e.preventDefault();
            executeScan(quickTargetInput.value.trim(), 'quick');
        });
    }

    async function executeScan(target, profileId = selectedScanProfile.profile_id) {
        hideElement(errorContainer);
        
        if (!target) {
            showError('Please enter a target hostname or IP address.');
            return;
        }

        const safePattern = /^[a-zA-Z0-9.:-]+$/;
        if (!safePattern.test(target)) {
            showError('Invalid target characters. Only letters, digits, dots, hyphens, and colons are allowed.');
            return;
        }

        if (target.startsWith('-')) {
            showError('Target cannot start with a hyphen.');
            return;
        }

        if (target.startsWith('.') || target.endsWith('.')) {
            showError('Target cannot start or end with a dot.');
            return;
        }

        setLoadingState(true);
        updateScanStatus('SCANNING');
        switchView('newScan');

        try {
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ target: target, profile_id: profileId })
            });

            const data = await response.json();

            if (!response.ok || data.status === 'error') {
                updateScanStatus('ERROR');
                if (response.status === 429) {
                    showToast('Rate limit reached: Maximum 10 scans per minute.', 'error');
                }
                showError(data.message || 'An error occurred during target scanning.');
            } else {
                updateScanStatus('COMPLETED');
                showToast(`Scan on ${data.target} completed successfully.`, 'success');
                renderResults(data);
                loadDashboardData();
            }
        } catch (err) {
            updateScanStatus('ERROR');
            showError('Failed to connect to the scanning service. Please check if the Flask server is running.');
        } finally {
            setLoadingState(false);
        }
    }

    function setLoadingState(isLoading) {
        if (isLoading) {
            targetInput.disabled = true;
            if (quickTargetInput) quickTargetInput.disabled = true;
            if (startScanBtn) startScanBtn.disabled = true;
            if (btnText) btnText.textContent = 'Auditing...';
            showElement(btnSpinner);
            showElement(loadingContainer);
        } else {
            targetInput.disabled = false;
            if (quickTargetInput) quickTargetInput.disabled = false;
            if (startScanBtn) startScanBtn.disabled = false;
            if (btnText) btnText.textContent = 'Execute Scan';
            hideElement(btnSpinner);
            hideElement(loadingContainer);
        }
    }

    function updateScanStatus(status) {
        if (!scanStatusBadge) return;
        scanStatusBadge.className = 'scan-status-badge';
        if (status === 'READY') {
            scanStatusBadge.classList.add('status-ready');
            scanStatusBadge.textContent = 'READY';
        } else if (status === 'SCANNING') {
            scanStatusBadge.classList.add('status-scanning');
            scanStatusBadge.textContent = 'SCANNING';
        } else if (status === 'COMPLETED') {
            scanStatusBadge.classList.add('status-completed');
            scanStatusBadge.textContent = 'COMPLETED';
        } else if (status === 'ERROR') {
            scanStatusBadge.classList.add('status-error');
            scanStatusBadge.textContent = 'ERROR';
        }
    }

    // =========================================================================
    // RESULTS INTERACTION
    // =========================================================================
    function renderResults(data) {
        resultsTableBody.innerHTML = '';
        resultTargetIp.textContent = data.target || '127.0.0.1';
        if (resultProfile) {
            const profile = data.scan_profile || {};
            resultProfile.textContent = profile.name
                ? `${profile.name} (${profile.flags || ''})`
                : 'Quick scan (-sT -F)';
        }
        
        const ports = data.ports || [];
        resultPortsCount.textContent = ports.length;
        resultStatus.textContent = (data.status || 'COMPLETED').toUpperCase();

        const VALID_RISKS = ['high', 'medium', 'low'];
        const rawRisk = (data.overall_risk || 'LOW').toLowerCase();
        const safeRisk = VALID_RISKS.includes(rawRisk) ? rawRisk : 'low';
        
        resultOverallRisk.textContent = (data.overall_risk || 'LOW').toUpperCase();
        
        // Dynamic styling classes matching CSS variables
        if (safeRisk === 'high') {
            resultOverallRisk.className = 'text-sm font-bold font-code text-error uppercase';
            resultStatus.className = 'text-sm font-bold text-error uppercase';
        } else if (safeRisk === 'medium') {
            resultOverallRisk.className = 'text-sm font-bold font-code text-tertiary-container uppercase';
            resultStatus.className = 'text-sm font-bold text-tertiary-container uppercase';
        } else {
            resultOverallRisk.className = 'text-sm font-bold font-code text-primary uppercase';
            resultStatus.className = 'text-sm font-bold text-green-500 uppercase';
        }

        let highCount = 0;
        let medCount = 0;
        let lowCount = 0;

        ports.forEach(p => {
            const r = (p.risk || 'LOW').toUpperCase();
            if (r === 'HIGH') highCount++;
            else if (r === 'MEDIUM') medCount++;
            else lowCount++;
        });

        resultBreakdownText.textContent = `${highCount} High · ${medCount} Med · ${lowCount} Low`;

        // Update Security Score summary item
        const scoreInfo = data.security_score || null;
        if (resultScoreNum && resultScoreLabel) {
            if (scoreInfo && scoreInfo.available && scoreInfo.score !== null) {
                resultScoreNum.textContent = `${scoreInfo.score}/100`;
                resultScoreLabel.textContent = scoreInfo.label || 'GOOD';
                const sBand = (scoreInfo.label || 'GOOD').toUpperCase();
                if (sBand === 'GOOD') {
                    resultScoreLabel.className = 'px-1.5 py-0.2 rounded text-[10px] font-bold border border-green-500/30 bg-green-500/10 text-green-500';
                } else if (sBand === 'FAIR') {
                    resultScoreLabel.className = 'px-1.5 py-0.2 rounded text-[10px] font-bold border border-tertiary-container/30 bg-tertiary-container/10 text-tertiary-container';
                } else if (sBand === 'NEEDS IMPROVEMENT') {
                    resultScoreLabel.className = 'px-1.5 py-0.2 rounded text-[10px] font-bold border border-amber-500/30 bg-amber-500/10 text-amber-800 dark:text-yellow-400';
                } else {
                    resultScoreLabel.className = 'px-1.5 py-0.2 rounded text-[10px] font-bold border border-error/30 bg-error/10 text-error';
                }
            } else {
                resultScoreNum.textContent = 'N/A';
                resultScoreLabel.textContent = 'UNAVAILABLE';
                resultScoreLabel.className = 'px-1.5 py-0.2 rounded text-[10px] font-bold border border-outline-variant bg-surface-container text-on-surface-variant';
            }
        }

        if (ports.length === 0) {
            hideElement(resultsTableWrapper);
            showElement(emptyPortsMessage);
        } else {
            showElement(resultsTableWrapper);
            hideElement(emptyPortsMessage);

            ports.forEach(item => {
                const tr = document.createElement('tr');
                tr.className = 'hover:bg-surface-container-highest/30 transition-colors';

                const tdPort = document.createElement('td');
                tdPort.className = 'p-3 font-code font-bold text-on-surface';
                tdPort.textContent = item.port;

                const tdProto = document.createElement('td');
                tdProto.className = 'p-3 text-on-surface-variant';
                tdProto.textContent = (item.protocol || 'tcp').toUpperCase();

                const tdState = document.createElement('td');
                tdState.className = 'p-3';
                const stateSpan = document.createElement('span');
                stateSpan.className = 'inline-flex items-center px-2 py-0.5 rounded-sm bg-primary/10 border border-primary/30 text-primary text-label-sm font-label-sm font-semibold';
                stateSpan.textContent = item.state || 'open';
                tdState.appendChild(stateSpan);

                const tdService = document.createElement('td');
                tdService.className = 'p-3 font-semibold text-primary';
                tdService.textContent = item.service || 'unknown';

                const tdRisk = document.createElement('td');
                tdRisk.className = 'p-3';
                const itemRisk = (item.risk || 'LOW').toLowerCase();
                const safeItemRisk = VALID_RISKS.includes(itemRisk) ? itemRisk : 'low';
                const riskSpan = document.createElement('span');
                
                if (safeItemRisk === 'high') {
                    riskSpan.className = 'inline-flex items-center px-2 py-0.5 rounded-sm bg-error/15 border border-error/30 text-error text-label-sm font-label-sm font-semibold';
                } else if (safeItemRisk === 'medium') {
                    riskSpan.className = 'inline-flex items-center px-2 py-0.5 rounded-sm bg-tertiary-container/15 border border-tertiary-container/30 text-tertiary-container text-label-sm font-label-sm font-semibold';
                } else {
                    riskSpan.className = 'inline-flex items-center px-2 py-0.5 rounded-sm bg-primary/15 border border-primary/30 text-primary text-label-sm font-label-sm font-semibold';
                }
                riskSpan.textContent = (item.risk || 'LOW').toUpperCase();
                tdRisk.appendChild(riskSpan);

                const tdReason = document.createElement('td');
                tdReason.className = 'p-3 text-on-surface-variant text-xs max-w-sm whitespace-normal';
                tdReason.textContent = item.reason || 'No details provided.';

                tr.appendChild(tdPort);
                tr.appendChild(tdProto);
                tr.appendChild(tdState);
                tr.appendChild(tdService);
                tr.appendChild(tdRisk);
                tr.appendChild(tdReason);

                resultsTableBody.appendChild(tr);
            });
        }

        currentScanId = data.scan_id || data.id || null;
        if (currentScanId) {
            exportReportLink.href = `/api/scan/${currentScanId}/export?format=txt`;
            if (exportReportPdfLink) exportReportPdfLink.href = `/api/scan/${currentScanId}/export?format=pdf`;
            if (exportReportCsvLink) exportReportCsvLink.href = `/api/scan/${currentScanId}/export?format=csv`;
            if (exportReportJsonLink) exportReportJsonLink.href = `/api/scan/${currentScanId}/export?format=json`;
            showElement(exportReportLink);
            if (exportReportPdfLink) showElement(exportReportPdfLink);
            if (exportReportCsvLink) showElement(exportReportCsvLink);
            if (exportReportJsonLink) showElement(exportReportJsonLink);
            initAiAnalyst(currentScanId);
        } else {
            hideElement(exportReportLink);
            if (exportReportPdfLink) hideElement(exportReportPdfLink);
            if (exportReportCsvLink) hideElement(exportReportCsvLink);
            if (exportReportJsonLink) hideElement(exportReportJsonLink);
            if (aiAnalystContainer) hideElement(aiAnalystContainer);
        }

        renderSecurityScoreWidget(data.security_score);
        renderServiceFingerprints(data.ports || []);
        renderRemediationPlaybook(data.ports || []);
        if (!copilotConversationId) {
            setCopilotActiveScope(data.target, currentScanId);
        }
        switchView('results');
    }

    // =========================================================================
    // DETERMINISTIC REMEDIATION PLAYBOOK CONTROLLER
    // =========================================================================
    function copyTextWithFeedback(text, buttonEl, originalLabel = 'Copy') {
        if (!text) return;
        const doSuccess = () => {
            if (buttonEl) {
                buttonEl.textContent = 'Copied!';
                buttonEl.classList.add('text-green-500');
                setTimeout(() => {
                    buttonEl.textContent = originalLabel;
                    buttonEl.classList.remove('text-green-500');
                }, 2000);
            }
        };

        if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.writeText(text).then(doSuccess).catch(() => {
                fallbackCopy(text, doSuccess);
            });
        } else {
            fallbackCopy(text, doSuccess);
        }
    }

    function fallbackCopy(text, onSuccess) {
        try {
            const ta = document.createElement('textarea');
            ta.value = text;
            ta.style.position = 'fixed';
            ta.style.left = '-9999px';
            document.body.appendChild(ta);
            ta.focus();
            ta.select();
            document.execCommand('copy');
            document.body.removeChild(ta);
            if (onSuccess) onSuccess();
        } catch (_) {
            showToast('Unable to copy to clipboard', 'error');
        }
    }

    function renderRemediationPlaybook(ports) {
        if (!remediationCardsContainer) return;
        remediationCardsContainer.innerHTML = '';

        if (!ports || ports.length === 0) {
            if (remediationEmptyMessage) showElement(remediationEmptyMessage);
            hideElement(remediationCardsContainer);
            return;
        }

        if (remediationEmptyMessage) hideElement(remediationEmptyMessage);
        showElement(remediationCardsContainer);

        ports.forEach((item) => {
            const rem = item.remediation || {};
            const card = document.createElement('div');
            card.className = 'bg-surface-container-low border border-outline-variant rounded p-4 flex flex-col gap-3';
            card.id = `remediation-card-${item.port}`;

            // Card Header
            const headerDiv = document.createElement('div');
            headerDiv.className = 'flex items-center justify-between border-b border-outline-variant pb-2.5 flex-wrap gap-2';

            const headerLeft = document.createElement('div');
            headerLeft.className = 'flex items-center gap-2';

            const portBadge = document.createElement('span');
            portBadge.className = 'font-code text-code text-xs font-bold px-2 py-0.5 rounded bg-surface-container-lowest border border-outline-variant text-primary';
            portBadge.textContent = `${item.port}/${item.protocol || 'tcp'}`;

            const serviceName = document.createElement('span');
            serviceName.className = 'font-bold text-sm text-on-surface uppercase';
            serviceName.textContent = item.service || 'unknown';

            headerLeft.appendChild(portBadge);
            headerLeft.appendChild(serviceName);

            const riskBadge = document.createElement('span');
            const riskUpper = (item.risk || 'LOW').toUpperCase();
            riskBadge.className = 'px-2 py-0.5 rounded text-label-sm font-label-sm font-bold border';
            if (riskUpper === 'HIGH') {
                riskBadge.classList.add('bg-error/10', 'border-error/30', 'text-error');
            } else if (riskUpper === 'MEDIUM') {
                riskBadge.classList.add('bg-tertiary-container/10', 'border-tertiary-container/30', 'text-tertiary-container');
            } else {
                riskBadge.classList.add('bg-primary/10', 'border-primary/30', 'text-primary');
            }
            riskBadge.textContent = `${riskUpper} RISK`;

            headerDiv.appendChild(headerLeft);
            headerDiv.appendChild(riskBadge);
            card.appendChild(headerDiv);

            // Summary
            if (rem.summary) {
                const summaryP = document.createElement('p');
                summaryP.className = 'text-body-sm text-on-surface leading-relaxed text-xs';
                summaryP.textContent = rem.summary;
                card.appendChild(summaryP);
            }

            // Steps
            if (rem.steps && rem.steps.length > 0) {
                const stepsSection = document.createElement('div');
                stepsSection.className = 'flex flex-col gap-1';

                const stepsTitle = document.createElement('span');
                stepsTitle.className = 'text-[11px] font-label-sm uppercase font-bold text-on-surface-variant';
                stepsTitle.textContent = 'Hardening Steps:';
                stepsSection.appendChild(stepsTitle);

                const stepsList = document.createElement('ul');
                stepsList.className = 'list-disc pl-4 space-y-1 text-xs text-on-surface';
                rem.steps.forEach((step) => {
                    const li = document.createElement('li');
                    li.textContent = step;
                    stepsList.appendChild(li);
                });
                stepsSection.appendChild(stepsList);
                card.appendChild(stepsSection);
            }

            // Platform Commands
            const platform = rem.platform || {};
            const platformsAvailable = Object.keys(platform).filter(k => Array.isArray(platform[k]) && platform[k].length > 0);

            if (platformsAvailable.length > 0) {
                const platformSection = document.createElement('div');
                platformSection.className = 'flex flex-col gap-2 pt-1 border-t border-outline-variant';

                const platformTitle = document.createElement('span');
                platformTitle.className = 'text-[11px] font-label-sm uppercase font-bold text-on-surface-variant';
                platformTitle.textContent = 'Illustrative Hardening Commands:';
                platformSection.appendChild(platformTitle);

                platformsAvailable.forEach((platKey) => {
                    const cmdGroup = document.createElement('div');
                    cmdGroup.className = 'bg-surface-container-lowest border border-outline-variant rounded p-2.5 flex flex-col gap-1.5';

                    const groupHeader = document.createElement('div');
                    groupHeader.className = 'flex items-center justify-between';

                    const platLabel = document.createElement('span');
                    platLabel.className = 'text-[10px] font-bold uppercase tracking-wider text-on-surface-variant';
                    platLabel.textContent = platKey === 'linux' ? 'Linux / systemd' : (platKey === 'windows' ? 'Windows PowerShell' : 'Perimeter Firewall');
                    groupHeader.appendChild(platLabel);

                    const allCmds = platform[platKey].join('\n');
                    const copyAllBtn = document.createElement('button');
                    copyAllBtn.type = 'button';
                    copyAllBtn.className = 'text-[11px] text-primary hover:text-primary-container font-code flex items-center gap-1 cursor-pointer transition-colors';
                    copyAllBtn.textContent = 'Copy Commands';
                    copyAllBtn.addEventListener('click', () => copyTextWithFeedback(allCmds, copyAllBtn, 'Copy Commands'));
                    groupHeader.appendChild(copyAllBtn);

                    cmdGroup.appendChild(groupHeader);

                    const pre = document.createElement('pre');
                    pre.className = 'font-code text-code text-[11px] text-on-surface overflow-x-auto p-2 bg-surface-container-low rounded border border-outline-variant/60 leading-relaxed';
                    pre.textContent = allCmds;
                    cmdGroup.appendChild(pre);

                    platformSection.appendChild(cmdGroup);
                });

                card.appendChild(platformSection);
            }

            // Verification Command
            if (rem.verification) {
                const verifSection = document.createElement('div');
                verifSection.className = 'flex items-center justify-between bg-surface-container-lowest border border-outline-variant rounded p-2 text-xs';

                const verifLeft = document.createElement('div');
                verifLeft.className = 'flex items-center gap-2 overflow-x-auto mr-2';

                const verifLabel = document.createElement('span');
                verifLabel.className = 'text-[10px] font-bold text-on-surface-variant uppercase shrink-0';
                verifLabel.textContent = 'Verification:';

                const verifCode = document.createElement('code');
                verifCode.className = 'font-code text-[11px] text-tertiary-container';
                verifCode.textContent = rem.verification;

                verifLeft.appendChild(verifLabel);
                verifLeft.appendChild(verifCode);

                const verifCopyBtn = document.createElement('button');
                verifCopyBtn.type = 'button';
                verifCopyBtn.className = 'text-[11px] text-primary hover:text-primary-container font-code shrink-0 cursor-pointer';
                verifCopyBtn.textContent = 'Copy';
                verifCopyBtn.addEventListener('click', () => copyTextWithFeedback(rem.verification, verifCopyBtn, 'Copy'));

                verifSection.appendChild(verifLeft);
                verifSection.appendChild(verifCopyBtn);
                card.appendChild(verifSection);
            }

            // Operational Warnings
            if (rem.warnings) {
                const warnBox = document.createElement('div');
                warnBox.className = 'p-2.5 bg-tertiary-container/10 border-l-2 border-l-tertiary-container rounded-r text-[11px] text-on-surface-variant flex items-start gap-1.5';

                const warnIcon = document.createElement('span');
                warnIcon.className = 'material-symbols-outlined text-tertiary-container text-[14px] shrink-0 mt-0.5';
                warnIcon.textContent = 'warning';

                const warnText = document.createElement('span');
                warnText.textContent = rem.warnings;

                warnBox.appendChild(warnIcon);
                warnBox.appendChild(warnText);
                card.appendChild(warnBox);
            }

            remediationCardsContainer.appendChild(card);
        });
    }

    // =========================================================================
    // DETERMINISTIC SECURITY SCORE CONTROLLER
    // =========================================================================
    function renderSecurityScoreWidget(scoreInfo) {
        if (!securityScoreWidget) return;

        if (!scoreInfo || !scoreInfo.available || scoreInfo.score === null || scoreInfo.score === undefined) {
            if (scoreDisplayNum) scoreDisplayNum.textContent = 'N/A';
            if (scoreBandBadge) {
                scoreBandBadge.textContent = 'UNAVAILABLE';
                scoreBandBadge.className = 'px-2 py-0.5 rounded text-xs font-bold border border-outline-variant bg-surface-container-lowest text-on-surface-variant';
            }
            if (scoreMeterFill) {
                scoreMeterFill.style.width = '0%';
                scoreMeterFill.className = 'h-full bg-outline-variant transition-all duration-500';
            }
            if (scoreTotalDeductions) {
                scoreTotalDeductions.textContent = 'Total Deductions: N/A';
            }
            if (scoreDeductionsList) {
                scoreDeductionsList.innerHTML = '';
                hideElement(scoreDeductionsList);
            }
            return;
        }

        const score = scoreInfo.score;
        const band = (scoreInfo.label || 'GOOD').toUpperCase();

        if (scoreDisplayNum) scoreDisplayNum.textContent = score;

        // Band styles and progress meter colors
        let badgeClass = 'px-2 py-0.5 rounded text-xs font-bold border ';
        let meterClass = 'h-full transition-all duration-500 ';

        if (band === 'GOOD') {
            badgeClass += 'bg-green-500/10 border-green-500/30 text-green-500';
            meterClass += 'bg-green-500';
        } else if (band === 'FAIR') {
            badgeClass += 'bg-tertiary-container/10 border-tertiary-container/30 text-tertiary-container';
            meterClass += 'bg-tertiary-container';
        } else if (band === 'NEEDS IMPROVEMENT') {
            badgeClass += 'bg-amber-500/10 border-amber-500/30 text-amber-800 dark:text-yellow-400';
            meterClass += 'bg-yellow-500';
        } else if (band === 'POOR') {
            badgeClass += 'bg-orange-500/10 border-orange-500/30 text-orange-500';
            meterClass += 'bg-orange-500';
        } else {
            badgeClass += 'bg-error/10 border-error/30 text-error';
            meterClass += 'bg-error';
        }

        if (scoreBandBadge) {
            scoreBandBadge.textContent = band;
            scoreBandBadge.className = badgeClass;
        }

        if (scoreMeterFill) {
            scoreMeterFill.className = meterClass;
            scoreMeterFill.style.width = `${Math.max(0, Math.min(100, score))}%`;
        }

        if (scoreTotalDeductions) {
            const totalDed = scoreInfo.total_deduction || 0;
            scoreTotalDeductions.textContent = `Total Deductions: -${totalDed} pts`;
        }

        if (scoreDeductionsList) {
            scoreDeductionsList.innerHTML = '';
            const deductions = scoreInfo.deductions || [];

            if (deductions.length === 0) {
                const emptyRow = document.createElement('div');
                emptyRow.className = 'text-on-surface-variant text-xs py-1 italic';
                emptyRow.textContent = 'No exposure penalties applied. All observed ports rated minimal risk or no open ports.';
                scoreDeductionsList.appendChild(emptyRow);
                showElement(scoreDeductionsList);
            } else {
                deductions.forEach(d => {
                    const row = document.createElement('div');
                    row.className = 'flex items-center justify-between p-2 rounded bg-surface-container-lowest border border-outline-variant flex-wrap gap-2 text-xs';

                    const left = document.createElement('div');
                    left.className = 'flex items-center gap-2 flex-wrap';

                    const portTag = document.createElement('span');
                    portTag.className = 'font-bold text-on-surface';
                    portTag.textContent = `Port ${d.port}/${d.protocol} · ${d.service}`;

                    const riskTag = document.createElement('span');
                    const r = (d.risk || 'LOW').toUpperCase();
                    riskTag.className = r === 'HIGH' ? 'px-1.5 py-0.2 rounded text-[10px] font-bold bg-error/15 text-error border border-error/30' : (r === 'MEDIUM' ? 'px-1.5 py-0.2 rounded text-[10px] font-bold bg-tertiary-container/15 text-tertiary-container border border-tertiary-container/30' : 'px-1.5 py-0.2 rounded text-[10px] font-bold bg-primary/15 text-primary border border-primary/30');
                    riskTag.textContent = r;

                    const reasonSpan = document.createElement('span');
                    reasonSpan.className = 'text-on-surface-variant text-[11px]';
                    reasonSpan.textContent = `— ${d.reason || ''}`;

                    left.appendChild(portTag);
                    left.appendChild(riskTag);
                    left.appendChild(reasonSpan);

                    const right = document.createElement('span');
                    right.className = 'font-bold text-error font-code';
                    right.textContent = `-${d.points_deducted} pts`;

                    row.appendChild(left);
                    row.appendChild(right);
                    scoreDeductionsList.appendChild(row);
                });
                showElement(scoreDeductionsList);
            }
        }
    }

    // =========================================================================
    // NETWORK SERVICE FINGERPRINTS CONTROLLER
    // =========================================================================
    function renderServiceFingerprints(ports) {
        if (!fingerprintsCardsContainer) return;
        fingerprintsCardsContainer.innerHTML = '';

        if (!ports || ports.length === 0) {
            if (fingerprintsEmptyMessage) showElement(fingerprintsEmptyMessage);
            hideElement(fingerprintsCardsContainer);
            return;
        }

        if (fingerprintsEmptyMessage) hideElement(fingerprintsEmptyMessage);
        showElement(fingerprintsCardsContainer);

        ports.forEach((item, index) => {
            const fp = item.fingerprint || {};
            const card = document.createElement('div');
            card.className = 'bg-surface-container-low border border-outline-variant rounded transition-all';

            // Card Header (clickable accordion toggle)
            const headerBtn = document.createElement('button');
            headerBtn.type = 'button';
            headerBtn.className = 'w-full p-4 flex items-center justify-between text-left hover:bg-surface-container transition-colors cursor-pointer focus:outline-none';
            headerBtn.setAttribute('aria-expanded', index === 0 ? 'true' : 'false');

            const headerLeft = document.createElement('div');
            headerLeft.className = 'flex items-center gap-3 flex-wrap';

            const portBadge = document.createElement('span');
            portBadge.className = 'font-code text-xs font-bold px-2 py-0.5 rounded bg-surface-container-lowest border border-outline-variant text-primary';
            portBadge.textContent = `Port ${item.port}/${item.protocol || 'tcp'}`;

            const nameSpan = document.createElement('span');
            nameSpan.className = 'font-bold text-sm text-on-surface';
            nameSpan.textContent = fp.display_name || `${(item.service || 'unknown').toUpperCase()} (Port ${item.port})`;

            const catBadge = document.createElement('span');
            catBadge.className = 'px-2 py-0.5 rounded text-[11px] font-semibold border border-outline-variant bg-surface-container text-on-surface-variant';
            catBadge.textContent = fp.category || 'Network Service';

            const riskUpper = (item.risk || fp.deterministic_risk || 'LOW').toUpperCase();
            const riskBadge = document.createElement('span');
            riskBadge.className = 'px-2 py-0.5 rounded text-label-sm font-label-sm font-bold border ';
            if (riskUpper === 'HIGH') {
                riskBadge.className += 'bg-error/10 border-error/30 text-error';
            } else if (riskUpper === 'MEDIUM') {
                riskBadge.className += 'bg-tertiary-container/10 border-tertiary-container/30 text-tertiary-container';
            } else {
                riskBadge.className += 'bg-primary/10 border-primary/30 text-primary';
            }
            riskBadge.textContent = `${riskUpper} RISK`;

            headerLeft.appendChild(portBadge);
            headerLeft.appendChild(nameSpan);
            headerLeft.appendChild(catBadge);
            headerLeft.appendChild(riskBadge);

            const headerRight = document.createElement('div');
            headerRight.className = 'flex items-center gap-2 text-on-surface-variant';
            const toggleIcon = document.createElement('span');
            toggleIcon.className = 'material-symbols-outlined text-[20px] transition-transform duration-200';
            toggleIcon.textContent = index === 0 ? 'expand_less' : 'expand_more';
            headerRight.appendChild(toggleIcon);

            headerBtn.appendChild(headerLeft);
            headerBtn.appendChild(headerRight);
            card.appendChild(headerBtn);

            // Card Body (Expandable content)
            const bodyDiv = document.createElement('div');
            bodyDiv.className = index === 0 ? 'p-4 border-t border-outline-variant flex flex-col gap-4' : 'hidden p-4 border-t border-outline-variant flex flex-col gap-4';

            // Toggle logic
            headerBtn.addEventListener('click', () => {
                const isExpanded = headerBtn.getAttribute('aria-expanded') === 'true';
                if (isExpanded) {
                    headerBtn.setAttribute('aria-expanded', 'false');
                    bodyDiv.classList.add('hidden');
                    toggleIcon.textContent = 'expand_more';
                } else {
                    headerBtn.setAttribute('aria-expanded', 'true');
                    bodyDiv.classList.remove('hidden');
                    toggleIcon.textContent = 'expand_less';
                }
            });

            // 1. Identification Method banner
            if (fp.identification_method) {
                const identDiv = document.createElement('div');
                identDiv.className = 'text-[11px] font-code text-on-surface-variant bg-surface-container-lowest px-3 py-1.5 rounded border border-outline-variant flex items-center justify-between flex-wrap gap-1';
                
                const identLeft = document.createElement('span');
                identLeft.className = 'flex items-center gap-1.5';
                const identIcon = document.createElement('span');
                identIcon.className = 'material-symbols-outlined text-[14px] text-primary';
                identIcon.textContent = 'search_check';
                const identText = document.createElement('span');
                identText.textContent = `Identification: ${fp.identification_method}`;
                identLeft.appendChild(identIcon);
                identLeft.appendChild(identText);

                const srvObserved = document.createElement('span');
                srvObserved.textContent = `Observed identifier: ${item.service || 'unknown'}`;

                identDiv.appendChild(identLeft);
                identDiv.appendChild(srvObserved);
                bodyDiv.appendChild(identDiv);
            }

            // 2. Protocol Description
            if (fp.description) {
                const descDiv = document.createElement('div');
                descDiv.className = 'flex flex-col gap-1';
                const descTitle = document.createElement('h5');
                descTitle.className = 'text-xs font-bold uppercase tracking-wider text-on-surface-variant';
                descTitle.textContent = 'Protocol Overview';
                const descP = document.createElement('p');
                descP.className = 'text-xs text-on-surface leading-relaxed';
                descP.textContent = fp.description;
                descDiv.appendChild(descTitle);
                descDiv.appendChild(descP);
                bodyDiv.appendChild(descDiv);
            }

            // 3. 2-Column Grid: Typical Usage & Common Security Concerns
            const gridRow1 = document.createElement('div');
            gridRow1.className = 'grid grid-cols-1 md:grid-cols-2 gap-3';

            // Typical Usage
            const usageCard = document.createElement('div');
            usageCard.className = 'p-3 rounded bg-surface-container border border-outline-variant flex flex-col gap-1';
            const usageTitle = document.createElement('span');
            usageTitle.className = 'text-xs font-bold text-primary flex items-center gap-1.5';
            const usageIcon = document.createElement('span');
            usageIcon.className = 'material-symbols-outlined text-[15px]';
            usageIcon.textContent = 'tune';
            const usageText = document.createElement('span');
            usageText.textContent = 'Typical Usage';
            usageTitle.appendChild(usageIcon);
            usageTitle.appendChild(usageText);
            const usageP = document.createElement('p');
            usageP.className = 'text-xs text-on-surface-variant leading-relaxed';
            usageP.textContent = fp.typical_use || 'Standard network service communications.';
            usageCard.appendChild(usageTitle);
            usageCard.appendChild(usageP);
            gridRow1.appendChild(usageCard);

            // Common Security Concerns
            const concernsCard = document.createElement('div');
            concernsCard.className = 'p-3 rounded bg-surface-container border border-outline-variant flex flex-col gap-1';
            const concernsTitle = document.createElement('span');
            concernsTitle.className = 'text-xs font-bold text-tertiary-container flex items-center gap-1.5';
            const concernsIcon = document.createElement('span');
            concernsIcon.className = 'material-symbols-outlined text-[15px]';
            concernsIcon.textContent = 'warning';
            const concernsText = document.createElement('span');
            concernsText.textContent = 'Security Concerns';
            concernsTitle.appendChild(concernsIcon);
            concernsTitle.appendChild(concernsText);
            const concernsP = document.createElement('p');
            concernsP.className = 'text-xs text-on-surface-variant leading-relaxed';
            concernsP.textContent = fp.common_security_concerns || 'General attack surface exposure.';
            concernsCard.appendChild(concernsTitle);
            concernsCard.appendChild(concernsP);
            gridRow1.appendChild(concernsCard);

            bodyDiv.appendChild(gridRow1);

            // 4. Associated Attacks / Threat Context & Public Exposure Guidance
            const gridRow2 = document.createElement('div');
            gridRow2.className = 'grid grid-cols-1 md:grid-cols-2 gap-3';

            // Associated Attacks & Threat Context (with explicit non-exploitability caveat!)
            const threatCard = document.createElement('div');
            threatCard.className = 'p-3 rounded bg-surface-container border border-error/25 flex flex-col gap-1';
            const threatTitle = document.createElement('span');
            threatTitle.className = 'text-xs font-bold text-error flex items-center gap-1.5';
            const threatIcon = document.createElement('span');
            threatIcon.className = 'material-symbols-outlined text-[15px]';
            threatIcon.textContent = 'shield_with_heart';
            const threatText = document.createElement('span');
            threatText.textContent = 'Associated Threat Context (Historical)';
            threatTitle.appendChild(threatIcon);
            threatTitle.appendChild(threatText);
            const threatP = document.createElement('p');
            threatP.className = 'text-xs text-on-surface-variant leading-relaxed';
            threatP.textContent = fp.associated_attacks || 'Probing, scanning, and password guessing.';
            threatCard.appendChild(threatTitle);
            threatCard.appendChild(threatP);
            gridRow2.appendChild(threatCard);

            // Public Exposure Guidance
            const exposureCard = document.createElement('div');
            exposureCard.className = 'p-3 rounded bg-surface-container border border-outline-variant flex flex-col gap-1';
            const expTitle = document.createElement('span');
            expTitle.className = 'text-xs font-bold text-on-surface flex items-center gap-1.5';
            const expIcon = document.createElement('span');
            expIcon.className = 'material-symbols-outlined text-[15px] text-primary';
            expIcon.textContent = 'public';
            const expText = document.createElement('span');
            expText.textContent = 'Public Exposure Guidance';
            expTitle.appendChild(expIcon);
            expTitle.appendChild(expText);
            const expP = document.createElement('p');
            expP.className = 'text-xs text-on-surface-variant leading-relaxed';
            expP.textContent = fp.public_exposure_guidance || 'Restrict network exposure if not essential.';
            exposureCard.appendChild(expTitle);
            exposureCard.appendChild(expP);
            gridRow2.appendChild(exposureCard);

            bodyDiv.appendChild(gridRow2);

            // 5. Defensive Recommendations
            const defRecs = fp.defensive_recommendations || [];
            if (defRecs.length > 0) {
                const recsDiv = document.createElement('div');
                recsDiv.className = 'p-3 rounded bg-surface-container-lowest border border-outline-variant flex flex-col gap-2';
                
                const recsTitle = document.createElement('span');
                recsTitle.className = 'text-xs font-bold text-on-surface flex items-center gap-1.5';
                const recsIcon = document.createElement('span');
                recsIcon.className = 'material-symbols-outlined text-[15px] text-primary';
                recsIcon.textContent = 'verified_user';
                const recsHead = document.createElement('span');
                recsHead.textContent = 'Defensive Hardening Recommendations';
                recsTitle.appendChild(recsIcon);
                recsTitle.appendChild(recsHead);
                recsDiv.appendChild(recsTitle);

                const recsUl = document.createElement('ul');
                recsUl.className = 'space-y-1.5 text-xs text-on-surface-variant list-disc list-inside';
                defRecs.forEach(rec => {
                    const li = document.createElement('li');
                    li.textContent = rec;
                    recsUl.appendChild(li);
                });
                recsDiv.appendChild(recsUl);
                bodyDiv.appendChild(recsDiv);
            }

            // 6. Authoritative References & Jump Link Row
            const footerRow = document.createElement('div');
            footerRow.className = 'flex items-center justify-between border-t border-outline-variant/60 pt-3 flex-wrap gap-2 text-xs';

            const refsDiv = document.createElement('div');
            refsDiv.className = 'flex items-center gap-2 flex-wrap text-on-surface-variant text-[11px]';
            const refsLabel = document.createElement('span');
            refsLabel.className = 'font-bold text-on-surface';
            refsLabel.textContent = 'References:';
            refsDiv.appendChild(refsLabel);

            const refs = fp.references || [];
            if (refs.length === 0) {
                const noneSpan = document.createElement('span');
                noneSpan.textContent = 'IANA Registry';
                refsDiv.appendChild(noneSpan);
            } else {
                refs.forEach(r => {
                    const a = document.createElement('a');
                    const safeUrl = (r.url && (r.url.startsWith('https://') || r.url.startsWith('http://'))) ? r.url : '#';
                    a.href = safeUrl;
                    a.target = '_blank';
                    a.rel = 'noopener noreferrer';
                    a.className = 'text-primary hover:underline inline-flex items-center gap-1';
                    a.textContent = r.title || 'Reference Documentation';
                    const extIcon = document.createElement('span');
                    extIcon.className = 'material-symbols-outlined text-[12px]';
                    extIcon.textContent = 'open_in_new';
                    a.appendChild(extIcon);
                    refsDiv.appendChild(a);
                });
            }
            footerRow.appendChild(refsDiv);

            // Jump to Remediation Playbook button
            const jumpBtn = document.createElement('button');
            jumpBtn.type = 'button';
            jumpBtn.className = 'btn text-[11px] font-semibold px-2.5 py-1 rounded bg-surface-container border border-primary/40 text-primary hover:bg-primary/10 flex items-center gap-1 cursor-pointer transition-colors';
            const jumpIcon = document.createElement('span');
            jumpIcon.className = 'material-symbols-outlined text-[14px]';
            jumpIcon.textContent = 'arrow_downward';
            const jumpLabel = document.createElement('span');
            jumpLabel.textContent = `Remediation Playbook (Port ${item.port})`;
            jumpBtn.appendChild(jumpIcon);
            jumpBtn.appendChild(jumpLabel);

            jumpBtn.addEventListener('click', () => {
                const targetCard = document.getElementById(`remediation-card-${item.port}`);
                if (targetCard) {
                    targetCard.scrollIntoView({ behavior: 'smooth', block: 'center' });
                    targetCard.classList.add('ring-2', 'ring-primary');
                    setTimeout(() => targetCard.classList.remove('ring-2', 'ring-primary'), 2500);
                } else if (remediationPlaybookSection) {
                    remediationPlaybookSection.scrollIntoView({ behavior: 'smooth' });
                }
            });
            footerRow.appendChild(jumpBtn);
            bodyDiv.appendChild(footerRow);

            // 7. Caveat / Limitations note
            if (fp.knowledge_limitations) {
                const limitNote = document.createElement('p');
                limitNote.className = 'text-[10px] text-on-surface-variant/80 italic flex items-center gap-1';
                const limitIcon = document.createElement('span');
                limitIcon.className = 'material-symbols-outlined text-[12px] text-on-surface-variant';
                limitIcon.textContent = 'info';
                const limitSpan = document.createElement('span');
                limitSpan.textContent = fp.knowledge_limitations;
                limitNote.appendChild(limitIcon);
                limitNote.appendChild(limitSpan);
                bodyDiv.appendChild(limitNote);
            }

            card.appendChild(bodyDiv);
            fingerprintsCardsContainer.appendChild(card);
        });
    }

    // =========================================================================
    // AI SECURITY ANALYST CONTROLLER
    // =========================================================================
    async function initAiAnalyst(scanId) {
        if (!aiAnalystContainer) return;
        showElement(aiAnalystContainer);

        // Reset display state
        hideElement(aiAssessmentResults);
        hideElement(aiStatusMessage);
        if (aiBadgeStatus) {
            aiBadgeStatus.className = 'px-2 py-0.5 rounded text-label-sm font-label-sm font-semibold border border-outline-variant bg-surface-container-lowest text-on-surface-variant';
            aiBadgeStatus.textContent = 'READY';
        }
        if (generateAiBtn) {
            generateAiBtn.disabled = false;
            generateAiBtnText.textContent = 'Generate AI Assessment';
            showElement(generateAiBtnIcon);
            hideElement(generateAiSpinner);
        }

        // Check if an AI assessment was already generated for this scan
        try {
            const res = await fetch(`/api/ai/analyze/${scanId}`);
            if (res.ok) {
                const data = await res.json();
                if (data.status === 'success' && data.analysis) {
                    renderAiAssessment(data.analysis, data.model);
                    if (aiBadgeStatus) {
                        aiBadgeStatus.className = 'px-2 py-0.5 rounded text-label-sm font-label-sm font-semibold border border-primary/30 bg-primary/10 text-primary';
                        aiBadgeStatus.textContent = 'ASSESSED';
                    }
                    if (generateAiBtnText) generateAiBtnText.textContent = 'Re-Analyze with AI';
                }
            }
        } catch (_) {
            // Background check failure is non-fatal
        }
    }

    if (generateAiBtn) {
        generateAiBtn.addEventListener('click', async () => {
            if (!currentScanId) {
                showToast('No active scan available for AI assessment.', 'error');
                return;
            }

            // Enter loading state
            generateAiBtn.disabled = true;
            generateAiBtnText.textContent = 'Analyzing findings...';
            hideElement(generateAiBtnIcon);
            showElement(generateAiSpinner);
            hideElement(aiStatusMessage);

            if (aiBadgeStatus) {
                aiBadgeStatus.className = 'px-2 py-0.5 rounded text-label-sm font-label-sm font-semibold border border-tertiary-container/30 bg-tertiary-container/10 text-tertiary-container animate-pulse';
                aiBadgeStatus.textContent = 'ANALYZING';
            }

            try {
                const res = await fetch(`/api/ai/analyze/${currentScanId}`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ force_refresh: true })
                });

                const data = await res.json();

                if (!res.ok || data.status !== 'success') {
                    if (aiBadgeStatus) {
                        aiBadgeStatus.className = 'px-2 py-0.5 rounded text-label-sm font-label-sm font-semibold border border-error/30 bg-error/10 text-error';
                        aiBadgeStatus.textContent = 'ERROR';
                    }
                    const msg = data.message || 'AI Security Assessment could not be generated.';
                    showToast(msg, 'error');
                    if (aiStatusMessage) {
                        aiStatusMessage.className = 'p-3 rounded text-xs border border-error/30 bg-error/10 text-error leading-relaxed';
                        aiStatusMessage.textContent = msg;
                        showElement(aiStatusMessage);
                    }
                    return;
                }

                // Render structured output
                renderAiAssessment(data.analysis, data.model);
                showToast('AI Security Assessment generated successfully.', 'success');

                if (aiBadgeStatus) {
                    aiBadgeStatus.className = 'px-2 py-0.5 rounded text-label-sm font-label-sm font-semibold border border-green-500/30 bg-green-500/10 text-green-500';
                    aiBadgeStatus.textContent = 'COMPLETED';
                }
                if (generateAiBtnText) generateAiBtnText.textContent = 'Re-Analyze with AI';

            } catch (err) {
                if (aiBadgeStatus) {
                    aiBadgeStatus.className = 'px-2 py-0.5 rounded text-label-sm font-label-sm font-semibold border border-error/30 bg-error/10 text-error';
                    aiBadgeStatus.textContent = 'OFFLINE';
                }
                const errMsg = 'Could not connect to the AI assessment service. Check that the Flask server is running.';
                showToast(errMsg, 'error');
                if (aiStatusMessage) {
                    aiStatusMessage.className = 'p-3 rounded text-xs border border-error/30 bg-error/10 text-error leading-relaxed';
                    aiStatusMessage.textContent = errMsg;
                    showElement(aiStatusMessage);
                }
            } finally {
                generateAiBtn.disabled = false;
                showElement(generateAiBtnIcon);
                hideElement(generateAiSpinner);
            }
        });
    }

    function renderAiAssessment(analysis, model) {
        if (!analysis || !aiAssessmentResults) return;

        // 1. Security Summary
        if (aiSummaryText) {
            aiSummaryText.textContent = analysis.summary || 'Summary unavailable.';
        }

        // 2. Key Findings list
        if (aiFindingsList) {
            aiFindingsList.innerHTML = '';
            const findings = analysis.findings || [];

            if (findings.length === 0) {
                const emptyCard = document.createElement('div');
                emptyCard.className = 'p-3 rounded bg-surface-container border border-outline-variant text-xs text-on-surface-variant';
                emptyCard.textContent = 'No open listening ports detected in this scan. Strong perimeter posture observed.';
                aiFindingsList.appendChild(emptyCard);
            } else {
                findings.forEach(f => {
                    const card = document.createElement('div');
                    card.className = 'p-3 rounded bg-surface-container border border-outline-variant flex flex-col gap-1.5';

                    // Top row: Port/Service + Risk Badge
                    const topRow = document.createElement('div');
                    topRow.className = 'flex items-center justify-between flex-wrap gap-2';

                    const portTitle = document.createElement('div');
                    portTitle.className = 'font-code font-bold text-sm text-on-surface flex items-center gap-2';
                    const icon = document.createElement('span');
                    icon.className = 'material-symbols-outlined text-[16px] text-primary';
                    icon.textContent = 'lan';
                    const portSpan = document.createElement('span');
                    portSpan.textContent = `Port ${f.port} · ${f.service || 'unknown'}`;
                    portTitle.appendChild(icon);
                    portTitle.appendChild(portSpan);

                    const riskBadge = document.createElement('span');
                    const r = (f.aegis_risk || 'LOW').toUpperCase();
                    if (r === 'HIGH') {
                        riskBadge.className = 'px-2 py-0.5 rounded-sm bg-error/15 border border-error/30 text-error text-label-sm font-label-sm font-semibold';
                    } else if (r === 'MEDIUM') {
                        riskBadge.className = 'px-2 py-0.5 rounded-sm bg-tertiary-container/15 border border-tertiary-container/30 text-tertiary-container text-label-sm font-label-sm font-semibold';
                    } else {
                        riskBadge.className = 'px-2 py-0.5 rounded-sm bg-primary/15 border border-primary/30 text-primary text-label-sm font-label-sm font-semibold';
                    }
                    riskBadge.textContent = r;

                    topRow.appendChild(portTitle);
                    topRow.appendChild(riskBadge);

                    // Body: Why it matters
                    const whyP = document.createElement('p');
                    whyP.className = 'text-xs text-on-surface leading-relaxed';
                    whyP.textContent = f.why_it_matters || 'Exposed listening socket.';

                    // Security Concern
                    const concernP = document.createElement('p');
                    concernP.className = 'text-xs text-on-surface-variant flex items-start gap-1.5 mt-0.5';
                    const alertIcon = document.createElement('span');
                    alertIcon.className = 'material-symbols-outlined text-[14px] text-tertiary-container shrink-0 mt-0.5';
                    alertIcon.textContent = 'security_update_warning';
                    const concernSpan = document.createElement('span');
                    concernSpan.textContent = f.security_concern || 'Review exposure scope.';
                    concernP.appendChild(alertIcon);
                    concernP.appendChild(concernSpan);

                    card.appendChild(topRow);
                    card.appendChild(whyP);
                    card.appendChild(concernP);
                    aiFindingsList.appendChild(card);
                });
            }
        }

        // 3. Priority Recommendations
        if (aiRecommendationsList) {
            aiRecommendationsList.innerHTML = '';
            const recs = analysis.recommendations || [];
            recs.forEach(rec => {
                const li = document.createElement('li');
                li.className = 'leading-relaxed text-body-sm text-on-surface';
                li.textContent = rec;
                aiRecommendationsList.appendChild(li);
            });
        }

        // 4. Beginner Explanation
        if (aiBeginnerText) {
            aiBeginnerText.textContent = analysis.beginner_explanation || '';
        }

        // 5. Verification Steps
        if (aiVerificationList) {
            aiVerificationList.innerHTML = '';
            const steps = analysis.verification_steps || [];
            steps.forEach(step => {
                const stepRow = document.createElement('div');
                stepRow.className = 'p-2 rounded bg-surface-container-lowest border border-outline-variant font-code text-code text-xs text-on-surface flex items-center gap-2 overflow-x-auto';
                const promptSign = document.createElement('span');
                promptSign.className = 'text-primary select-none font-bold';
                promptSign.textContent = '$';
                const stepCode = document.createElement('span');
                stepCode.textContent = step;
                stepRow.appendChild(promptSign);
                stepRow.appendChild(stepCode);
                aiVerificationList.appendChild(stepRow);
            });
        }

        // 6. Metadata
        if (aiModelMeta) {
            const engineName = model || analysis._model || 'Aegis AI Analyst';
            aiModelMeta.textContent = `Engine: ${engineName}`;
        }

        showElement(aiAssessmentResults);
    }

    // =========================================================================
    // LOAD STATISTICS AND PERSISTED RUNS
    // =========================================================================
    async function loadDashboardData() {
        try {
            const [statsRes, historyRes, vizRes] = await Promise.all([
                fetch('/api/stats'),
                fetch('/api/history'),
                fetch('/api/stats/visualizations')
            ]);

            if (statsRes.ok) {
                const stats = await statsRes.json();
                updateStats(stats);
            }

            if (historyRes.ok) {
                const history = await historyRes.json();
                renderHistory(history);
                renderReports(history);
            }

            if (vizRes && vizRes.ok) {
                const viz = await vizRes.json();
                renderVisualizations(viz);
            }
        } catch (_) {
            // Fails silently without crashing core inputs
        }
    }

    function updateStats(stats) {
        document.getElementById('stat-total-scans').textContent = stats.total_scans || 0;
        document.getElementById('stat-total-ports').textContent = stats.total_open_ports || 0;
        document.getElementById('stat-high-risk').textContent = stats.high_risk_count || 0;
        document.getElementById('stat-medium-risk').textContent = stats.medium_risk_count || 0;
        document.getElementById('stat-low-risk').textContent = stats.low_risk_count || 0;

        // Sync report summary counters too
        const rTotalScans = document.getElementById('reports-total-scans');
        const rHigh = document.getElementById('reports-high-findings');
        if (rTotalScans) rTotalScans.textContent = stats.total_scans || 0;
        if (rHigh) rHigh.textContent = stats.high_risk_count || 0;

        // Dynamic risk bar update
        const high = stats.high_risk_count || 0;
        const med = stats.medium_risk_count || 0;
        const low = stats.low_risk_count || 0;
        const total = high + med + low;

        const barSegmentHigh = document.getElementById('bar-segment-high');
        const barSegmentMed = document.getElementById('bar-segment-medium');
        const barSegmentLow = document.getElementById('bar-segment-low');
        const barSegmentEmpty = document.getElementById('bar-segment-empty');

        const legendCountHigh = document.getElementById('legend-count-high');
        const legendCountMed = document.getElementById('legend-count-medium');
        const legendCountLow = document.getElementById('legend-count-low');

        const legendPctHigh = document.getElementById('legend-pct-high');
        const legendPctMed = document.getElementById('legend-pct-medium');
        const legendPctLow = document.getElementById('legend-pct-low');

        if (legendCountHigh) legendCountHigh.textContent = high;
        if (legendCountMed) legendCountMed.textContent = med;
        if (legendCountLow) legendCountLow.textContent = low;

        if (total > 0) {
            const pctHigh = Math.round((high / total) * 100);
            const pctMed = Math.round((med / total) * 100);
            const pctLow = 100 - pctHigh - pctMed;

            if (barSegmentHigh) barSegmentHigh.style.width = `${pctHigh}%`;
            if (barSegmentMed) barSegmentMed.style.width = `${pctMed}%`;
            if (barSegmentLow) barSegmentLow.style.width = `${pctLow}%`;
            if (barSegmentEmpty) barSegmentEmpty.style.width = '0%';

            if (legendPctHigh) legendPctHigh.textContent = `(${pctHigh}%)`;
            if (legendPctMed) legendPctMed.textContent = `(${pctMed}%)`;
            if (legendPctLow) legendPctLow.textContent = `(${pctLow}%)`;
        } else {
            if (barSegmentHigh) barSegmentHigh.style.width = '0%';
            if (barSegmentMed) barSegmentMed.style.width = '0%';
            if (barSegmentLow) barSegmentLow.style.width = '0%';
            if (barSegmentEmpty) barSegmentEmpty.style.width = '100%';

            if (legendPctHigh) legendPctHigh.textContent = '(0%)';
            if (legendPctMed) legendPctMed.textContent = '(0%)';
            if (legendPctLow) legendPctLow.textContent = '(0%)';
        }
    }

    // =========================================================================
    // VISUAL RISK DASHBOARD (PURE SVG CHARTS)
    // =========================================================================
    function renderVisualizations(viz) {
        if (!viz) return;
        renderDonutChart(viz.risk_distribution);
        renderTargetsBarChart(viz.top_targets, viz.summary);
        renderTimelineChart(viz.activity_timeline, viz.summary);
    }

    function renderDonutChart(dist) {
        const container = document.getElementById('chart-donut-container');
        if (!container) return;
        container.innerHTML = '';

        const high = dist ? (dist.high || 0) : 0;
        const med = dist ? (dist.medium || 0) : 0;
        const low = dist ? (dist.low || 0) : 0;
        const total = high + med + low;

        const pHigh = dist && dist.percentages ? (dist.percentages.high || 0) : 0;
        const pMed = dist && dist.percentages ? (dist.percentages.medium || 0) : 0;
        const pLow = dist && dist.percentages ? (dist.percentages.low || 0) : 0;

        const dHighStat = document.getElementById('donut-high-stat');
        const dMedStat = document.getElementById('donut-med-stat');
        const dLowStat = document.getElementById('donut-low-stat');
        const dHighPct = document.getElementById('donut-high-pct');
        const dMedPct = document.getElementById('donut-med-pct');
        const dLowPct = document.getElementById('donut-low-pct');

        if (dHighStat) dHighStat.textContent = `${high} High`;
        if (dMedStat) dMedStat.textContent = `${med} Med`;
        if (dLowStat) dLowStat.textContent = `${low} Low`;
        if (dHighPct) dHighPct.textContent = `${pHigh}%`;
        if (dMedPct) dMedPct.textContent = `${pMed}%`;
        if (dLowPct) dLowPct.textContent = `${pLow}%`;

        const svgNS = 'http://www.w3.org/2000/svg';
        const svg = document.createElementNS(svgNS, 'svg');
        svg.setAttribute('viewBox', '0 0 100 100');
        svg.setAttribute('class', 'w-32 h-32 my-1');
        svg.setAttribute('role', 'img');
        svg.setAttribute('aria-label', `Risk severity donut chart: ${high} High, ${med} Medium, ${low} Low findings out of ${total} total findings.`);

        const r = 36;
        const c = 2 * Math.PI * r;

        // Background track circle
        const bgCircle = document.createElementNS(svgNS, 'circle');
        bgCircle.setAttribute('cx', '50');
        bgCircle.setAttribute('cy', '50');
        bgCircle.setAttribute('r', r);
        bgCircle.setAttribute('fill', 'none');
        bgCircle.setAttribute('stroke', 'var(--outline-variant)');
        bgCircle.setAttribute('stroke-width', '10');
        bgCircle.setAttribute('opacity', '0.25');
        svg.appendChild(bgCircle);

        if (total > 0) {
            let offset = 0;
            const segments = [
                { count: high, color: 'var(--error, #ffb4ab)' },
                { count: med, color: 'var(--tertiary-container, #e47014)' },
                { count: low, color: 'var(--primary, #acc7ff)' }
            ];

            segments.forEach(seg => {
                if (seg.count > 0) {
                    const strokeLen = (seg.count / total) * c;
                    const circle = document.createElementNS(svgNS, 'circle');
                    circle.setAttribute('cx', '50');
                    circle.setAttribute('cy', '50');
                    circle.setAttribute('r', r);
                    circle.setAttribute('fill', 'none');
                    circle.setAttribute('stroke', seg.color);
                    circle.setAttribute('stroke-width', '10');
                    circle.setAttribute('stroke-dasharray', `${strokeLen} ${c - strokeLen}`);
                    circle.setAttribute('stroke-dashoffset', `${-offset}`);
                    circle.setAttribute('transform', 'rotate(-90 50 50)');
                    circle.setAttribute('stroke-linecap', 'butt');
                    svg.appendChild(circle);
                    offset += strokeLen;
                }
            });
        }

        const textCount = document.createElementNS(svgNS, 'text');
        textCount.setAttribute('x', '50');
        textCount.setAttribute('y', '47');
        textCount.setAttribute('text-anchor', 'middle');
        textCount.setAttribute('dominant-baseline', 'central');
        textCount.setAttribute('fill', 'var(--on-surface)');
        textCount.setAttribute('font-size', '15');
        textCount.setAttribute('font-weight', 'bold');
        textCount.setAttribute('font-family', 'JetBrains Mono, monospace');
        textCount.textContent = total;
        svg.appendChild(textCount);

        const textLabel = document.createElementNS(svgNS, 'text');
        textLabel.setAttribute('x', '50');
        textLabel.setAttribute('y', '61');
        textLabel.setAttribute('text-anchor', 'middle');
        textLabel.setAttribute('fill', 'var(--on-surface-variant)');
        textLabel.setAttribute('font-size', '6.5');
        textLabel.setAttribute('font-weight', '600');
        textLabel.setAttribute('letter-spacing', '0.05em');
        textLabel.textContent = 'FINDINGS';
        svg.appendChild(textLabel);

        container.appendChild(svg);
    }

    function renderTargetsBarChart(topTargets, summary) {
        const container = document.getElementById('chart-targets-container');
        if (!container) return;
        container.innerHTML = '';

        const countLabel = document.getElementById('chart-unique-targets-count');
        if (countLabel) {
            const count = summary ? (summary.unique_targets || 0) : (topTargets ? topTargets.length : 0);
            countLabel.textContent = `${count} Total Hosts`;
        }

        if (!topTargets || topTargets.length === 0) {
            const emptyP = document.createElement('p');
            emptyP.className = 'text-xs text-on-surface-variant text-center py-6';
            emptyP.textContent = 'No host scan records logged yet.';
            container.appendChild(emptyP);
            return;
        }

        const maxCount = Math.max(...topTargets.map(t => t.scan_count || 1), 1);
        const wrapper = document.createElement('div');
        wrapper.className = 'flex flex-col gap-2 w-full py-1';
        wrapper.setAttribute('role', 'list');
        wrapper.setAttribute('aria-label', 'Top audited targets frequency list');

        topTargets.forEach(item => {
            const row = document.createElement('div');
            row.className = 'flex flex-col gap-1 w-full';
            row.setAttribute('role', 'listitem');

            const header = document.createElement('div');
            header.className = 'flex items-center justify-between text-xs font-code';

            const nameSpan = document.createElement('span');
            nameSpan.className = 'text-on-surface font-semibold truncate max-w-[140px]';
            nameSpan.textContent = item.target;

            const badgeSpan = document.createElement('span');
            badgeSpan.className = 'text-[10px] text-on-surface-variant flex items-center gap-1.5';
            
            const countStrong = document.createElement('strong');
            countStrong.className = 'text-primary';
            countStrong.textContent = `${item.scan_count} ${item.scan_count === 1 ? 'scan' : 'scans'}`;
            badgeSpan.appendChild(countStrong);

            if (item.latest_risk) {
                const riskPill = document.createElement('span');
                const r = String(item.latest_risk).toUpperCase();
                riskPill.className = r === 'HIGH' ? 'text-error font-bold' : (r === 'MEDIUM' ? 'text-tertiary-container font-bold' : 'text-primary font-bold');
                riskPill.textContent = `[${r}]`;
                badgeSpan.appendChild(riskPill);
            }

            header.appendChild(nameSpan);
            header.appendChild(badgeSpan);

            const track = document.createElement('div');
            track.className = 'w-full h-1.5 rounded-full bg-surface-container-lowest border border-outline-variant overflow-hidden';

            const fill = document.createElement('div');
            const pct = Math.max(Math.round((item.scan_count / maxCount) * 100), 6);
            fill.className = 'h-full bg-primary rounded-full transition-all duration-300';
            fill.style.width = `${pct}%`;

            track.appendChild(fill);
            row.appendChild(header);
            row.appendChild(track);
            wrapper.appendChild(row);
        });

        container.appendChild(wrapper);
    }

    function renderTimelineChart(timeline, summary) {
        const container = document.getElementById('chart-timeline-container');
        if (!container) return;
        container.innerHTML = '';

        const countLabel = document.getElementById('chart-timeline-scans-count');
        if (countLabel) {
            const count = summary ? (summary.total_scans || 0) : (timeline ? timeline.reduce((acc, t) => acc + (t.scan_count || 0), 0) : 0);
            countLabel.textContent = `${count} Runs Logged`;
        }

        if (!timeline || timeline.length === 0) {
            const emptyP = document.createElement('p');
            emptyP.className = 'text-xs text-on-surface-variant text-center py-6';
            emptyP.textContent = 'No historical scan timeline available.';
            container.appendChild(emptyP);
            return;
        }

        const maxCount = Math.max(...timeline.map(t => t.scan_count || 1), 1);
        const svgNS = 'http://www.w3.org/2000/svg';
        const svg = document.createElementNS(svgNS, 'svg');
        svg.setAttribute('viewBox', '0 0 240 100');
        svg.setAttribute('class', 'w-full h-28');
        svg.setAttribute('role', 'img');
        svg.setAttribute('aria-label', `Scan activity timeline showing ${timeline.length} time points`);

        const baselineY = 82;
        const chartHeight = 58;
        const totalItems = timeline.length;
        const colWidth = Math.max(Math.min(Math.floor(200 / totalItems) - 6, 26), 10);
        const step = Math.floor(220 / Math.max(totalItems, 1));

        const baseLine = document.createElementNS(svgNS, 'line');
        baseLine.setAttribute('x1', '10');
        baseLine.setAttribute('y1', baselineY);
        baseLine.setAttribute('x2', '230');
        baseLine.setAttribute('y2', baselineY);
        baseLine.setAttribute('stroke', 'var(--outline-variant)');
        baseLine.setAttribute('stroke-width', '1');
        svg.appendChild(baseLine);

        timeline.forEach((item, idx) => {
            const x = 15 + idx * step;
            const barH = Math.max(Math.round((item.scan_count / maxCount) * chartHeight), 4);
            const y = baselineY - barH;

            const rect = document.createElementNS(svgNS, 'rect');
            rect.setAttribute('x', x);
            rect.setAttribute('y', y);
            rect.setAttribute('width', colWidth);
            rect.setAttribute('height', barH);
            rect.setAttribute('rx', '2');
            rect.setAttribute('fill', 'var(--primary, #acc7ff)');
            rect.setAttribute('class', 'hover:opacity-80 transition-opacity cursor-pointer');

            const titleElem = document.createElementNS(svgNS, 'title');
            titleElem.textContent = `${item.date}: ${item.scan_count} scan(s)`;
            rect.appendChild(titleElem);
            svg.appendChild(rect);

            const txtVal = document.createElementNS(svgNS, 'text');
            txtVal.setAttribute('x', x + colWidth / 2);
            txtVal.setAttribute('y', Math.max(y - 3, 10));
            txtVal.setAttribute('text-anchor', 'middle');
            txtVal.setAttribute('fill', 'var(--on-surface-variant)');
            txtVal.setAttribute('font-size', '7');
            txtVal.setAttribute('font-family', 'JetBrains Mono, monospace');
            txtVal.textContent = item.scan_count;
            svg.appendChild(txtVal);

            const dateParts = item.date.split(' ');
            const shortDate = dateParts.length >= 2 ? `${dateParts[0]} ${dateParts[1].slice(0, 3)}` : item.date.slice(0, 6);
            const txtDate = document.createElementNS(svgNS, 'text');
            txtDate.setAttribute('x', x + colWidth / 2);
            txtDate.setAttribute('y', baselineY + 12);
            txtDate.setAttribute('text-anchor', 'middle');
            txtDate.setAttribute('fill', 'var(--on-surface-variant)');
            txtDate.setAttribute('font-size', '6.5');
            txtDate.setAttribute('font-family', 'JetBrains Mono, monospace');
            txtDate.textContent = shortDate;
            svg.appendChild(txtDate);
        });

        container.appendChild(svg);
    }

    // =========================================================================
    // SCAN COMPARISON CONTROLLER (EXPOSURE DIFF)
    // =========================================================================
    let cachedHistoryForCompare = [];

    async function loadCompareOptions() {
        if (!compareBaseSelect || !compareTargetSelect) return;

        try {
            const res = await fetch('/api/history');
            if (!res.ok) return;
            const history = await res.json();
            cachedHistoryForCompare = history || [];

            compareBaseSelect.innerHTML = '<option value="">Select baseline scan (earlier)...</option>';
            compareTargetSelect.innerHTML = '<option value="">Select compared scan (later)...</option>';

            if (cachedHistoryForCompare.length < 2) {
                if (compareStatusBadge) compareStatusBadge.textContent = 'NEED 2+ SCANS';
                showErrorInCompare('At least two historical scans are required to compute an exposure comparison.');
                return;
            }

            hideErrorInCompare();
            if (compareStatusBadge) compareStatusBadge.textContent = 'READY';

            cachedHistoryForCompare.forEach(scan => {
                const optA = document.createElement('option');
                optA.value = scan.id;
                optA.textContent = `#${scan.id} — ${scan.target} (${scan.scan_time}) [${scan.open_port_count} ports, ${scan.overall_risk}]`;
                optA.setAttribute('data-target', scan.target);
                compareBaseSelect.appendChild(optA);

                const optB = document.createElement('option');
                optB.value = scan.id;
                optB.textContent = `#${scan.id} — ${scan.target} (${scan.scan_time}) [${scan.open_port_count} ports, ${scan.overall_risk}]`;
                optB.setAttribute('data-target', scan.target);
                compareTargetSelect.appendChild(optB);
            });

            autoSelectMatchingScans();

        } catch (_) {
            showErrorInCompare('Failed to retrieve historical audits for comparison.');
        }
    }

    function autoSelectMatchingScans() {
        if (!cachedHistoryForCompare || cachedHistoryForCompare.length < 2) return;

        const byTarget = {};
        cachedHistoryForCompare.forEach(s => {
            const key = s.target.trim().toLowerCase();
            if (!byTarget[key]) byTarget[key] = [];
            byTarget[key].push(s);
        });

        for (const key of Object.keys(byTarget)) {
            if (byTarget[key].length >= 2) {
                const scans = byTarget[key];
                scans.sort((a, b) => a.id - b.id);
                compareBaseSelect.value = scans[0].id;
                compareTargetSelect.value = scans[scans.length - 1].id;
                return;
            }
        }

        compareBaseSelect.value = cachedHistoryForCompare[cachedHistoryForCompare.length - 1].id;
        compareTargetSelect.value = cachedHistoryForCompare[0].id;
    }

    if (compareBaseSelect) {
        compareBaseSelect.addEventListener('change', () => {
            const selectedBaseId = parseInt(compareBaseSelect.value, 10);
            if (!selectedBaseId) return;

            const baseScan = cachedHistoryForCompare.find(s => s.id === selectedBaseId);
            if (!baseScan) return;

            const targetNorm = baseScan.target.trim().toLowerCase();
            const currentTargetVal = parseInt(compareTargetSelect.value, 10);
            const currentTargetScan = cachedHistoryForCompare.find(s => s.id === currentTargetVal);

            if (!currentTargetScan || currentTargetScan.target.trim().toLowerCase() !== targetNorm || currentTargetScan.id === selectedBaseId) {
                const match = cachedHistoryForCompare.find(s => s.target.trim().toLowerCase() === targetNorm && s.id !== selectedBaseId);
                if (match) {
                    compareTargetSelect.value = match.id;
                    hideErrorInCompare();
                }
            }
        });
    }

    if (executeCompareBtn) {
        executeCompareBtn.addEventListener('click', () => {
            const baseId = compareBaseSelect ? compareBaseSelect.value : null;
            const targetId = compareTargetSelect ? compareTargetSelect.value : null;
            executeComparison(baseId, targetId);
        });
    }

    async function executeComparison(baseId, targetId) {
        hideErrorInCompare();

        if (!baseId || !targetId) {
            showErrorInCompare('Please select both a baseline scan and a compared scan.');
            return;
        }

        if (baseId === targetId) {
            showErrorInCompare('Cannot compare a scan against itself. Please select two distinct audits.');
            return;
        }

        setCompareLoading(true);
        if (compareStatusBadge) compareStatusBadge.textContent = 'COMPARING...';

        try {
            const res = await fetch(`/api/scan/compare?base_id=${encodeURIComponent(baseId)}&target_id=${encodeURIComponent(targetId)}`);
            const data = await res.json();

            if (!res.ok || data.status !== 'success') {
                if (compareStatusBadge) compareStatusBadge.textContent = 'ERROR';
                showErrorInCompare(data.message || 'Comparison failed.');
                return;
            }

            renderComparisonResults(data);
            if (compareStatusBadge) compareStatusBadge.textContent = 'COMPLETED';
            showToast('Scan comparison computed successfully.', 'success');

        } catch (err) {
            if (compareStatusBadge) compareStatusBadge.textContent = 'ERROR';
            showErrorInCompare('Could not connect to comparison service. Check that the Flask server is running.');
        } finally {
            setCompareLoading(false);
        }
    }

    function setCompareLoading(isLoading) {
        if (isLoading) {
            showElement(compareLoadingContainer);
            hideElement(compareEmptyState);
            hideElement(compareResultsContainer);
            if (executeCompareBtn) executeCompareBtn.disabled = true;
            if (compareBtnIcon) hideElement(compareBtnIcon);
            if (compareBtnSpinner) showElement(compareBtnSpinner);
            if (compareBtnText) compareBtnText.textContent = 'Comparing...';
        } else {
            hideElement(compareLoadingContainer);
            if (executeCompareBtn) executeCompareBtn.disabled = false;
            if (compareBtnIcon) showElement(compareBtnIcon);
            if (compareBtnSpinner) hideElement(compareBtnSpinner);
            if (compareBtnText) compareBtnText.textContent = 'Compare Scans';
        }
    }

    function showErrorInCompare(msg) {
        if (compareErrorMessage) compareErrorMessage.textContent = msg;
        showElement(compareErrorContainer);
        hideElement(compareResultsContainer);
        showElement(compareEmptyState);
    }

    function hideErrorInCompare() {
        hideElement(compareErrorContainer);
    }

    function renderComparisonResults(data) {
        hideElement(compareEmptyState);
        hideElement(compareErrorContainer);

        if (compareTargetName) compareTargetName.textContent = data.target || '127.0.0.1';
        if (compareSummaryText) compareSummaryText.textContent = data.summary || '';

        if (compareEarlierId) compareEarlierId.textContent = `Scan #${data.earlier_scan.id}`;
        if (compareEarlierTime) compareEarlierTime.textContent = `Timestamp: ${data.earlier_scan.scan_time}`;
        if (compareEarlierProfile) compareEarlierProfile.textContent = `${data.earlier_scan.profile_name} (${data.earlier_scan.profile_flags})`;
        if (compareEarlierPorts) compareEarlierPorts.textContent = `${data.earlier_scan.open_port_count} ports (${data.earlier_scan.overall_risk})`;

        if (compareLaterId) compareLaterId.textContent = `Scan #${data.later_scan.id}`;
        if (compareLaterTime) compareLaterTime.textContent = `Timestamp: ${data.later_scan.scan_time}`;
        if (compareLaterProfile) compareLaterProfile.textContent = `${data.later_scan.profile_name} (${data.later_scan.profile_flags})`;
        if (compareLaterPorts) compareLaterPorts.textContent = `${data.later_scan.open_port_count} ports (${data.later_scan.overall_risk})`;

        const eScore = data.earlier_scan && data.earlier_scan.security_score;
        const lScore = data.later_scan && data.later_scan.security_score;
        const scoreCmp = data.security_score_comparison || {};

        if (compareEarlierScore) {
            if (eScore && eScore.available && eScore.score !== null && eScore.score !== undefined) {
                compareEarlierScore.textContent = `${eScore.score}/100 (${eScore.label})`;
            } else {
                compareEarlierScore.textContent = 'Unavailable';
            }
        }

        if (compareLaterScore) {
            if (lScore && lScore.available && lScore.score !== null && lScore.score !== undefined) {
                compareLaterScore.textContent = `${lScore.score}/100 (${lScore.label})`;
            } else {
                compareLaterScore.textContent = 'Unavailable';
            }
        }

        if (compareScoreDeltaBanner && compareScoreDeltaVal && compareScoreDeltaInterpretation) {
            if (scoreCmp && scoreCmp.score_delta !== undefined && scoreCmp.score_delta !== null) {
                const delta = scoreCmp.score_delta;
                const prefix = delta > 0 ? '+' : '';
                compareScoreDeltaVal.textContent = `${prefix}${delta} pts`;
                if (delta > 0) {
                    compareScoreDeltaVal.className = 'font-code font-bold text-xs px-2 py-0.5 rounded bg-primary/10 border border-primary/30 text-primary';
                } else if (delta < 0) {
                    compareScoreDeltaVal.className = 'font-code font-bold text-xs px-2 py-0.5 rounded bg-error/10 border border-error/30 text-error';
                } else {
                    compareScoreDeltaVal.className = 'font-code font-bold text-xs px-2 py-0.5 rounded bg-surface-container-lowest border border-outline-variant text-on-surface';
                }
                compareScoreDeltaInterpretation.textContent = scoreCmp.interpretation || '';
                showElement(compareScoreDeltaBanner);
            } else {
                hideElement(compareScoreDeltaBanner);
            }
        }

        if (compareProfileWarning && compareProfileWarningText) {
            if (data.profile_discrepancy) {
                compareProfileWarningText.textContent = data.profile_discrepancy;
                showElement(compareProfileWarning);
            } else {
                hideElement(compareProfileWarning);
            }
        }

        const counts = data.counts || {};
        if (compareCountNew) compareCountNew.textContent = `+${counts.newly_detected || 0}`;
        if (compareCountMissing) compareCountMissing.textContent = `-${counts.not_detected || 0}`;
        if (compareCountChanged) compareCountChanged.textContent = `~${counts.changed_service || 0}`;
        if (compareCountUnchanged) compareCountUnchanged.textContent = `=${counts.unchanged || 0}`;

        // 1. Newly Detected Ports
        if (compareNewPortsList) {
            compareNewPortsList.innerHTML = '';
            const newPorts = data.newly_detected || [];
            if (newPorts.length === 0) {
                const emptyCard = document.createElement('div');
                emptyCard.className = 'p-3 rounded bg-surface-container border border-outline-variant text-on-surface-variant text-xs';
                emptyCard.textContent = 'No newly detected open ports in the later scan.';
                compareNewPortsList.appendChild(emptyCard);
            } else {
                newPorts.forEach(item => {
                    const card = document.createElement('div');
                    card.className = 'p-3 rounded bg-surface-container border border-error/30 flex flex-col gap-1.5';

                    const topRow = document.createElement('div');
                    topRow.className = 'flex items-center justify-between flex-wrap gap-2';

                    const titleSpan = document.createElement('span');
                    titleSpan.className = 'font-bold text-on-surface text-sm flex items-center gap-1.5';
                    titleSpan.textContent = `Port ${item.port}/${item.protocol} · ${item.service} (NEW)`;

                    const riskSpan = document.createElement('span');
                    const r = (item.risk || 'LOW').toUpperCase();
                    riskSpan.className = r === 'HIGH' ? 'px-2 py-0.5 rounded-sm bg-error/15 border border-error/30 text-error font-bold text-xs' : (r === 'MEDIUM' ? 'px-2 py-0.5 rounded-sm bg-tertiary-container/15 border border-tertiary-container/30 text-tertiary-container font-bold text-xs' : 'px-2 py-0.5 rounded-sm bg-primary/15 border border-primary/30 text-primary font-bold text-xs');
                    riskSpan.textContent = r;

                    topRow.appendChild(titleSpan);
                    topRow.appendChild(riskSpan);

                    const impactP = document.createElement('p');
                    impactP.className = 'text-xs text-error font-semibold leading-relaxed';
                    impactP.textContent = item.exposure_impact || 'Newly exposed attack vector.';

                    const reasonP = document.createElement('p');
                    reasonP.className = 'text-xs text-on-surface-variant leading-relaxed';
                    reasonP.textContent = item.reason || '';

                    const remedP = document.createElement('p');
                    remedP.className = 'text-xs text-on-surface leading-relaxed border-t border-outline-variant/60 pt-1 mt-1';
                    const remedStrong = document.createElement('strong');
                    remedStrong.className = 'text-primary';
                    remedStrong.textContent = 'Suggested Action: ';
                    remedP.appendChild(remedStrong);
                    const remedText = document.createTextNode(item.remediation || '');
                    remedP.appendChild(remedText);

                    card.appendChild(topRow);
                    card.appendChild(impactP);
                    card.appendChild(reasonP);
                    card.appendChild(remedP);
                    compareNewPortsList.appendChild(card);
                });
            }
        }

        // 2. Ports Not Detected in Later Scan
        if (compareMissingPortsList) {
            compareMissingPortsList.innerHTML = '';
            const missingPorts = data.not_detected || [];
            if (missingPorts.length === 0) {
                const emptyCard = document.createElement('div');
                emptyCard.className = 'p-3 rounded bg-surface-container border border-outline-variant text-on-surface-variant text-xs';
                emptyCard.textContent = 'All ports from the baseline scan were also observed in the later scan.';
                compareMissingPortsList.appendChild(emptyCard);
            } else {
                missingPorts.forEach(item => {
                    const card = document.createElement('div');
                    card.className = 'p-3 rounded bg-surface-container border border-tertiary-container/30 flex flex-col gap-1.5';

                    const topRow = document.createElement('div');
                    topRow.className = 'flex items-center justify-between flex-wrap gap-2';

                    const titleSpan = document.createElement('span');
                    titleSpan.className = 'font-bold text-on-surface text-sm flex items-center gap-1.5';
                    titleSpan.textContent = `Port ${item.port}/${item.protocol} · ${item.service} (NOT DETECTED LATER)`;

                    const riskSpan = document.createElement('span');
                    riskSpan.className = 'px-2 py-0.5 rounded-sm bg-tertiary-container/15 border border-tertiary-container/30 text-tertiary-container font-bold text-xs';
                    riskSpan.textContent = `WAS ${item.risk}`;

                    topRow.appendChild(titleSpan);
                    topRow.appendChild(riskSpan);

                    const noteP = document.createElement('p');
                    noteP.className = 'text-xs text-on-surface-variant leading-relaxed';
                    noteP.textContent = item.status_note || 'Port was not detected in the later scan.';

                    card.appendChild(topRow);
                    card.appendChild(noteP);
                    compareMissingPortsList.appendChild(card);
                });
            }
        }

        // 3. Changed Service Information
        if (compareChangedPortsList) {
            compareChangedPortsList.innerHTML = '';
            const changedPorts = data.changed_service || [];
            if (changedPorts.length === 0) {
                const emptyCard = document.createElement('div');
                emptyCard.className = 'p-3 rounded bg-surface-container border border-outline-variant text-on-surface-variant text-xs';
                emptyCard.textContent = 'No service definition changes detected across common ports.';
                compareChangedPortsList.appendChild(emptyCard);
            } else {
                changedPorts.forEach(item => {
                    const card = document.createElement('div');
                    card.className = 'p-3 rounded bg-surface-container border border-primary/30 flex flex-col gap-1.5';

                    const topRow = document.createElement('div');
                    topRow.className = 'flex items-center justify-between flex-wrap gap-2';

                    const titleSpan = document.createElement('span');
                    titleSpan.className = 'font-bold text-on-surface text-sm';
                    titleSpan.textContent = `Port ${item.port}/${item.protocol} · Changed from '${item.earlier_service}' to '${item.later_service}'`;

                    const riskSpan = document.createElement('span');
                    riskSpan.className = 'px-2 py-0.5 rounded-sm bg-primary/15 border border-primary/30 text-primary font-bold text-xs';
                    riskSpan.textContent = item.risk || 'LOW';

                    topRow.appendChild(titleSpan);
                    topRow.appendChild(riskSpan);

                    const noteP = document.createElement('p');
                    noteP.className = 'text-xs text-on-surface-variant leading-relaxed';
                    noteP.textContent = item.change_summary || '';

                    card.appendChild(topRow);
                    card.appendChild(noteP);
                    compareChangedPortsList.appendChild(card);
                });
            }
        }

        // 4. Unchanged Ports
        if (compareUnchangedPortsList) {
            compareUnchangedPortsList.innerHTML = '';
            const unchangedPorts = data.unchanged || [];
            if (unchangedPorts.length === 0) {
                const emptyCard = document.createElement('div');
                emptyCard.className = 'p-3 rounded bg-surface-container border border-outline-variant text-on-surface-variant text-xs';
                emptyCard.textContent = 'No unchanged ports between the two audits.';
                compareUnchangedPortsList.appendChild(emptyCard);
            } else {
                unchangedPorts.forEach(item => {
                    const card = document.createElement('div');
                    card.className = 'p-2.5 rounded bg-surface-container border border-outline-variant flex items-center justify-between flex-wrap gap-2 text-xs';

                    const leftSpan = document.createElement('span');
                    leftSpan.className = 'text-on-surface font-semibold flex items-center gap-2';
                    const icon = document.createElement('span');
                    icon.className = 'material-symbols-outlined text-[15px] text-green-500';
                    icon.textContent = 'check';
                    const textSpan = document.createElement('span');
                    textSpan.textContent = `Port ${item.port}/${item.protocol} · ${item.service} (${item.state})`;
                    leftSpan.appendChild(icon);
                    leftSpan.appendChild(textSpan);

                    const riskSpan = document.createElement('span');
                    const r = (item.risk || 'LOW').toUpperCase();
                    riskSpan.className = r === 'HIGH' ? 'text-error font-bold' : (r === 'MEDIUM' ? 'text-tertiary-container font-bold' : 'text-primary font-bold');
                    riskSpan.textContent = r;

                    card.appendChild(leftSpan);
                    card.appendChild(riskSpan);
                    compareUnchangedPortsList.appendChild(card);
                });
            }
        }

        if (compareCaveatsText) {
            compareCaveatsText.textContent = data.caveats || '';
        }

        showElement(compareResultsContainer);
    }

    // =========================================================================
    // RENDERING CORE LISTS
    // =========================================================================
    function renderHistory(scans) {
        // Clear history views
        historyTableBody.innerHTML = '';
        const dbHistoryBody = document.getElementById('dashboard-history-body');
        const dbEmptyState = document.getElementById('dashboard-empty-state');
        if (dbHistoryBody) dbHistoryBody.innerHTML = '';

        if (!scans || scans.length === 0) {
            hideElement(historyTableWrapper);
            showElement(emptyHistoryBox);
            
            if (dbHistoryBody) hideElement(document.getElementById('dashboard-history-wrapper'));
            showElement(dbEmptyState);
            return;
        }

        showElement(historyTableWrapper);
        hideElement(emptyHistoryBox);
        
        if (dbHistoryBody) showElement(document.getElementById('dashboard-history-wrapper'));
        hideElement(dbEmptyState);

        const VALID_RISKS = ['high', 'medium', 'low'];

        scans.forEach((scan, idx) => {
            // 1. Build row for the Scan History Tab
            const tr = document.createElement('tr');
            tr.className = 'hover:bg-surface-container-highest/30 transition-all duration-150';

            const tdTarget = document.createElement('td');
            tdTarget.className = 'p-3 font-code font-bold text-on-surface';
            tdTarget.textContent = scan.target;

            const tdTime = document.createElement('td');
            tdTime.className = 'p-3 text-on-surface-variant font-code';
            tdTime.textContent = scan.scan_time;

            const tdPorts = document.createElement('td');
            tdPorts.className = 'p-3 text-primary font-code font-bold';
            tdPorts.textContent = `${scan.open_port_count} ${scan.open_port_count === 1 ? 'port' : 'ports'}`;

            const tdRisk = document.createElement('td');
            tdRisk.className = 'p-3';
            const rawRisk = (scan.overall_risk || 'LOW').toLowerCase();
            const safeRisk = VALID_RISKS.includes(rawRisk) ? rawRisk : 'low';
            const riskSpan = document.createElement('span');
            
            if (safeRisk === 'high') {
                riskSpan.className = 'inline-flex items-center px-2 py-0.5 rounded-sm bg-error/15 border border-error/30 text-error font-label-sm text-label-sm font-semibold';
            } else if (safeRisk === 'medium') {
                riskSpan.className = 'inline-flex items-center px-2 py-0.5 rounded-sm bg-tertiary-container/15 border border-tertiary-container/30 text-tertiary-container font-label-sm text-label-sm font-semibold';
            } else {
                riskSpan.className = 'inline-flex items-center px-2 py-0.5 rounded-sm bg-primary/15 border border-primary/30 text-primary font-label-sm text-label-sm font-semibold';
            }
            riskSpan.textContent = (scan.overall_risk || 'LOW').toUpperCase();
            tdRisk.appendChild(riskSpan);

            const tdStatus = document.createElement('td');
            tdStatus.className = 'p-3';
            const statusSpan = document.createElement('span');
            statusSpan.className = 'inline-flex items-center px-2 py-0.5 rounded-sm bg-secondary-container text-on-secondary-container border border-outline-variant text-label-sm font-label-sm';
            statusSpan.textContent = 'Completed';
            tdStatus.appendChild(statusSpan);

            const tdAction = document.createElement('td');
            tdAction.className = 'p-3 text-right';
            const viewBtn = document.createElement('button');
            viewBtn.type = 'button';
            viewBtn.className = 'text-primary hover:text-primary-container font-bold text-xs uppercase cursor-pointer';
            viewBtn.textContent = 'View';
            viewBtn.setAttribute('aria-label', `View scan ${scan.id}`);
            viewBtn.addEventListener('click', () => loadScanDetails(scan.id));
            tdAction.appendChild(viewBtn);

            tr.appendChild(tdTarget);
            tr.appendChild(tdTime);
            tr.appendChild(tdPorts);
            tr.appendChild(tdRisk);
            tr.appendChild(tdStatus);
            tr.appendChild(tdAction);
            historyTableBody.appendChild(tr);

            // 2. Build row for Dashboard Tab (Show max last 5 scans)
            if (idx < 5 && dbHistoryBody) {
                const dbTr = document.createElement('tr');
                dbTr.className = 'hover:bg-surface-container-highest transition-colors cursor-pointer';
                dbTr.addEventListener('click', () => loadScanDetails(scan.id));

                const dbTdTarget = document.createElement('td');
                dbTdTarget.className = 'p-3 font-bold';
                dbTdTarget.textContent = scan.target;

                const dbTdTime = document.createElement('td');
                dbTdTime.className = 'p-3 text-on-surface-variant';
                dbTdTime.textContent = scan.scan_time;

                const dbTdPorts = document.createElement('td');
                dbTdPorts.textContent = `${scan.open_port_count} open`;
                dbTdPorts.className = 'p-3';

                const dbTdRisk = document.createElement('td');
                dbTdRisk.className = 'p-3';
                const dbRiskSpan = document.createElement('span');
                dbRiskSpan.className = safeRisk === 'high' ? 'text-error font-semibold' : (safeRisk === 'medium' ? 'text-tertiary-container font-semibold' : 'text-primary font-semibold');
                dbRiskSpan.textContent = (scan.overall_risk || 'LOW').toUpperCase();
                dbTdRisk.appendChild(dbRiskSpan);

                const dbTdStatus = document.createElement('td');
                dbTdStatus.className = 'p-3';
                const dbStatusSpan = document.createElement('span');
                dbStatusSpan.className = 'px-1.5 py-0.5 rounded bg-surface-container-lowest border border-outline-variant text-on-surface font-label-sm text-label-sm';
                dbStatusSpan.textContent = 'Completed';
                dbTdStatus.appendChild(dbStatusSpan);

                dbTr.appendChild(dbTdTarget);
                dbTr.appendChild(dbTdTime);
                dbTr.appendChild(dbTdPorts);
                dbTr.appendChild(dbTdRisk);
                dbTr.appendChild(dbTdStatus);
                dbHistoryBody.appendChild(dbTr);
            }
        });
    }

    function renderReports(scans) {
        const reportsTableBody = document.getElementById('reports-table-body');
        const reportsEmptyState = document.getElementById('reports-empty-state');
        if (!reportsTableBody) return;

        reportsTableBody.innerHTML = '';
        if (!scans || scans.length === 0) {
            showElement(reportsEmptyState);
            hideElement(document.getElementById('reports-table-body').closest('table'));
            return;
        }

        hideElement(reportsEmptyState);
        showElement(document.getElementById('reports-table-body').closest('table'));

        scans.forEach(scan => {
            const tr = document.createElement('tr');
            tr.className = 'hover:bg-surface-container-highest/50 transition-colors group';

            const tdId = document.createElement('td');
            tdId.className = 'p-3 text-code font-code text-on-surface-variant';
            tdId.textContent = `#${scan.id}`;

            const tdName = document.createElement('td');
            tdName.className = 'p-3 font-medium flex items-center gap-2';
            
            const rawRisk = (scan.overall_risk || 'LOW').toLowerCase();
            const iconSpan = document.createElement('span');
            iconSpan.className = 'material-symbols-outlined text-[16px]';
            if (rawRisk === 'high') {
                iconSpan.classList.add('text-error');
                iconSpan.textContent = 'flag';
            } else if (rawRisk === 'medium') {
                iconSpan.classList.add('text-tertiary-container');
                iconSpan.textContent = 'warning';
            } else {
                iconSpan.classList.add('text-primary');
                iconSpan.textContent = 'security';
            }

            const textSpan = document.createElement('span');
            textSpan.textContent = `Aegis_Report_${scan.target.replace(/[^a-zA-Z0-9]/g, '_')}`;

            tdName.appendChild(iconSpan);
            tdName.appendChild(textSpan);

            const tdTarget = document.createElement('td');
            tdTarget.className = 'p-3 text-code font-code';
            tdTarget.textContent = scan.target;

            const tdType = document.createElement('td');
            tdType.className = 'p-3';
            const typeSpan = document.createElement('span');
            typeSpan.className = 'inline-flex items-center px-2 py-0.5 rounded-sm bg-primary/10 border border-primary/30 text-primary text-label-sm font-label-sm';
            typeSpan.textContent = 'Vulnerability';
            tdType.appendChild(typeSpan);

            const tdGenerated = document.createElement('td');
            tdGenerated.className = 'p-3 text-on-surface-variant';
            tdGenerated.textContent = scan.scan_time;

            const tdAction = document.createElement('td');
            tdAction.className = 'p-3 text-right whitespace-nowrap';
            
            const createExportLink = (format, iconName, label, colorClass) => {
                const link = document.createElement('a');
                link.href = `/api/scan/${scan.id}/export?format=${format}`;
                link.className = `${colorClass || 'text-on-surface-variant'} hover:text-primary p-1 rounded hover:bg-surface-container inline-flex items-center text-xs ml-1 transition-colors`;
                link.setAttribute('download', '');
                link.setAttribute('title', `Download ${label}`);
                link.setAttribute('aria-label', `Download ${label}`);
                const icon = document.createElement('span');
                icon.className = 'material-symbols-outlined text-[16px]';
                icon.textContent = iconName;
                link.appendChild(icon);
                return link;
            };

            tdAction.appendChild(createExportLink('pdf', 'picture_as_pdf', 'PDF Report', 'text-error'));
            tdAction.appendChild(createExportLink('csv', 'table_chart', 'CSV Spreadsheet', 'text-tertiary-container'));
            tdAction.appendChild(createExportLink('json', 'data_object', 'JSON Data', 'text-primary'));
            tdAction.appendChild(createExportLink('txt', 'description', 'TXT Log', 'text-on-surface-variant'));

            tr.appendChild(tdId);
            tr.appendChild(tdName);
            tr.appendChild(tdTarget);
            tr.appendChild(tdType);
            tr.appendChild(tdGenerated);
            tr.appendChild(tdAction);
            reportsTableBody.appendChild(tr);
        });
    }

    async function loadScanDetails(scanId) {
        try {
            const response = await fetch(`/api/scan/${scanId}`);
            const data = await response.json();
            if (!response.ok) throw new Error(data.message);
            data.scan_id = data.id;
            renderResults(data);
        } catch (error) {
            showError(error.message || 'Unable to retrieve saved scan details.');
        }
    }

    // =========================================================================
    // CLEAR HISTORY (CONFIRMATION MODAL & DELETE API)
    // =========================================================================
    if (clearHistoryBtn) {
        clearHistoryBtn.addEventListener('click', () => {
            showElement(confirmModal);
        });
    }

    if (modalCancelBtn) {
        modalCancelBtn.addEventListener('click', () => {
            hideElement(confirmModal);
        });
    }

    if (confirmModal) {
        confirmModal.addEventListener('click', (e) => {
            if (e.target === confirmModal) {
                hideElement(confirmModal);
            }
        });
    }

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            if (confirmModal && !confirmModal.classList.contains('hidden')) {
                hideElement(confirmModal);
            }
            if (copilotConfirmModal && !copilotConfirmModal.classList.contains('hidden')) {
                closeCopilotModal();
            }
        }
        if (e.altKey && (e.key === 'c' || e.key === 'C')) {
            e.preventDefault();
            switchView('copilot');
            const copilotInput = document.getElementById('copilot-input-text');
            if (copilotInput) copilotInput.focus();
        }
    });

    if (modalConfirmBtn) {
        modalConfirmBtn.addEventListener('click', async () => {
            try {
                modalConfirmBtn.disabled = true;
                modalConfirmBtn.textContent = 'Clearing...';

                const response = await fetch('/api/history', {
                    method: 'DELETE'
                });

                const data = await response.json();

                if (!response.ok || data.status === 'error') {
                    showToast(data.message || 'Failed to clear scan history.', 'error');
                } else {
                    hideElement(confirmModal);
                    showToast('Scan history cleared successfully.', 'success');
                    hideElement(resultsContainer);
                    loadDashboardData();
                    switchView('dashboard');
                }
            } catch (_) {
                showToast('Failed to connect to database service.', 'error');
            } finally {
                modalConfirmBtn.disabled = false;
                modalConfirmBtn.textContent = 'Clear All Records';
                hideElement(confirmModal);
            }
        });
    }

    // =========================================================================
    // GENERAL EXPORT CLICKS
    // =========================================================================
    const exportTextBtn = document.getElementById('report-export-text-btn');
    const exportJsonBtn = document.getElementById('report-export-json-btn');
    const exportPdfBtn = document.getElementById('report-export-pdf-btn');
    const exportCsvBtn = document.getElementById('report-export-csv-btn');

    async function triggerExportForLatest(format, formatLabel) {
        if (currentScanId) {
            window.location.href = `/api/scan/${currentScanId}/export?format=${format}`;
            showToast(`Downloading ${formatLabel} for Scan #${currentScanId}...`, 'info');
            return;
        }
        try {
            const res = await fetch('/api/history');
            if (res.ok) {
                const scans = await res.json();
                if (scans && scans.length > 0) {
                    window.location.href = `/api/scan/${scans[0].id}/export?format=${format}`;
                    showToast(`Downloading latest ${formatLabel} (Scan #${scans[0].id})...`, 'info');
                    return;
                }
            }
        } catch (_) {}
        showToast('No scans found in database. Execute a scan first.', 'error');
    }

    if (exportPdfBtn) {
        exportPdfBtn.addEventListener('click', () => triggerExportForLatest('pdf', 'Executive PDF'));
    }
    if (exportCsvBtn) {
        exportCsvBtn.addEventListener('click', () => triggerExportForLatest('csv', 'Structured CSV'));
    }
    if (exportJsonBtn) {
        exportJsonBtn.addEventListener('click', () => triggerExportForLatest('json', 'Structured JSON'));
    }
    if (exportTextBtn) {
        exportTextBtn.addEventListener('click', () => triggerExportForLatest('txt', 'Technical Text Log'));
    }

    // =========================================================================
    // AEGIS AI COPILOT CONTROLLER
    // =========================================================================
    let copilotActiveTarget = '127.0.0.1';
    let copilotActiveScanId = null;
    let copilotConversationId = null;
    let pendingExecutionPlan = null;
    let activePollInterval = null;

    const copilotStatusBadge = document.getElementById('copilot-status-badge');
    const copilotActiveTargetEl = document.getElementById('copilot-active-target');
    const copilotActiveScanBadge = document.getElementById('copilot-active-scan-badge');
    const copilotNewChatBtn = document.getElementById('copilot-new-chat-btn');
    const copilotWelcomeCard = document.getElementById('copilot-welcome-card');
    const copilotChatContainer = document.getElementById('copilot-chat-container');
    const copilotChatFeed = document.getElementById('copilot-chat-feed');
    const copilotInputForm = document.getElementById('copilot-input-form');
    const copilotInputText = document.getElementById('copilot-input-text');
    const copilotSubmitBtn = document.getElementById('copilot-submit-btn');

    // Execution Confirmation Modal Elements
    const copilotConfirmModal = document.getElementById('copilot-confirm-modal');
    const copilotModalClose = document.getElementById('copilot-modal-close');
    const copilotModalTarget = document.getElementById('copilot-modal-target');
    const copilotModalOperation = document.getElementById('copilot-modal-operation');
    const copilotModalCommand = document.getElementById('copilot-modal-command');
    const copilotModalWarning = document.getElementById('copilot-modal-warning');
    const copilotModalAuthCheck = document.getElementById('copilot-modal-auth-check');
    const copilotModalCancelBtn = document.getElementById('copilot-modal-cancel-btn');
    const copilotModalExecuteBtn = document.getElementById('copilot-modal-execute-btn');

    function setCopilotActiveScope(target, scanId) {
        if (target) copilotActiveTarget = target;
        copilotActiveScanId = scanId || null;
        if (copilotActiveTargetEl) copilotActiveTargetEl.textContent = copilotActiveTarget;
        if (copilotActiveScanBadge) {
            copilotActiveScanBadge.textContent = copilotActiveScanId ? `[Scan #${copilotActiveScanId}]` : '[Ad-hoc]';
        }
    }

    function setCopilotStatus(status, type = 'ready') {
        if (!copilotStatusBadge) return;
        copilotStatusBadge.textContent = status.toUpperCase();
        if (type === 'thinking') {
            copilotStatusBadge.className = 'px-2 py-0.5 rounded text-[10px] font-bold border border-tertiary-container/30 bg-tertiary-container/10 text-tertiary-container animate-pulse';
        } else if (type === 'executing') {
            copilotStatusBadge.className = 'px-2 py-0.5 rounded text-[10px] font-bold border border-primary/30 bg-primary/10 text-primary animate-pulse';
        } else if (type === 'error') {
            copilotStatusBadge.className = 'px-2 py-0.5 rounded text-[10px] font-bold border border-error/30 bg-error/10 text-error';
        } else {
            copilotStatusBadge.className = 'px-2 py-0.5 rounded text-[10px] font-bold border border-green-500/30 bg-green-500/10 text-green-500';
        }
    }

    function resetCopilotSession() {
        if (activePollInterval) {
            clearInterval(activePollInterval);
            activePollInterval = null;
        }
        copilotConversationId = null;
        if (copilotChatFeed) copilotChatFeed.innerHTML = '';
        if (copilotWelcomeCard) showElement(copilotWelcomeCard);
        setCopilotStatus('READY', 'ready');
        showToast('Started a new Copilot session.', 'info');
    }

    if (copilotNewChatBtn) {
        copilotNewChatBtn.addEventListener('click', resetCopilotSession);
    }

    // Sidebar quick input form
    const sidebarCopilotForm = document.getElementById('sidebar-copilot-quick-form');
    const sidebarCopilotInput = document.getElementById('sidebar-copilot-quick-input');
    if (sidebarCopilotForm && sidebarCopilotInput) {
        sidebarCopilotForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const prompt = sidebarCopilotInput.value.trim();
            if (!prompt) return;
            sidebarCopilotInput.value = '';
            switchView('copilot');
            if (copilotInputText) {
                copilotInputText.value = prompt;
                handleCopilotSubmit();
            }
        });
    }

    // Starter chips click handler
    document.querySelectorAll('.copilot-starter-chip').forEach(chip => {
        chip.addEventListener('click', () => {
            const prompt = chip.getAttribute('data-prompt');
            if (prompt && copilotInputText) {
                copilotInputText.value = prompt;
                handleCopilotSubmit();
            }
        });
    });

    if (copilotInputForm) {
        copilotInputForm.addEventListener('submit', (e) => {
            e.preventDefault();
            handleCopilotSubmit();
        });
    }

    async function handleCopilotSubmit() {
        if (!copilotInputText) return;
        const message = copilotInputText.value.trim();
        if (!message) return;

        copilotInputText.value = '';
        if (copilotWelcomeCard) hideElement(copilotWelcomeCard);

        // 1. Render User message bubble (safe DOM)
        appendCopilotUserMessage(message);

        // 2. Set thinking state & render temporary thinking bubble
        if (copilotSubmitBtn) copilotSubmitBtn.disabled = true;
        setCopilotStatus('THINKING...', 'thinking');
        const thinkingBubble = appendCopilotThinkingBubble();
        scrollChatToBottom();

        try {
            const res = await fetch('/api/copilot/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    message: message,
                    conversation_id: copilotConversationId,
                    target: copilotActiveTarget,
                    scan_id: copilotActiveScanId
                })
            });

            const data = await res.json();
            thinkingBubble.remove();

            if (!res.ok || data.status === 'error') {
                setCopilotStatus('ERROR', 'error');
                appendCopilotErrorMessage(data.message || 'An error occurred while consulting Copilot.');
                showToast(data.message || 'Copilot query failed.', 'error');
                return;
            }

            // Update conversation tracking
            if (data.conversation_id) {
                copilotConversationId = data.conversation_id;
            }
            if (data.target) {
                copilotActiveTarget = data.target;
                if (copilotActiveTargetEl) copilotActiveTargetEl.textContent = copilotActiveTarget;
            }
            if (data.scan_id !== undefined) {
                copilotActiveScanId = data.scan_id;
                if (copilotActiveScanBadge) {
                    copilotActiveScanBadge.textContent = copilotActiveScanId ? `[Scan #${copilotActiveScanId}]` : '[Ad-hoc]';
                }
            }

            // Render Assistant Response
            appendCopilotAssistantMessage(data.reply, data.suggested_command);
            setCopilotStatus('READY', 'ready');

        } catch (err) {
            thinkingBubble.remove();
            setCopilotStatus('ERROR', 'error');
            appendCopilotErrorMessage('Unable to connect to Copilot service. Please check network/server status.');
            showToast('Failed to connect to Copilot service.', 'error');
        } finally {
            if (copilotSubmitBtn) copilotSubmitBtn.disabled = false;
            scrollChatToBottom();
        }
    }

    function scrollChatToBottom() {
        if (copilotChatContainer) {
            copilotChatContainer.scrollTop = copilotChatContainer.scrollHeight;
        }
    }

    function appendCopilotUserMessage(text) {
        if (!copilotChatFeed) return;
        const row = document.createElement('div');
        row.className = 'flex items-start gap-3 justify-end';

        const bubble = document.createElement('div');
        bubble.className = 'max-w-[85%] rounded-lg p-3 bg-primary text-on-primary text-xs leading-relaxed space-y-1 shadow-sm';

        const senderRow = document.createElement('div');
        senderRow.className = 'font-bold text-[10px] opacity-80 flex items-center justify-end gap-1 font-label-sm';
        senderRow.textContent = 'YOU';

        const content = document.createElement('div');
        content.className = 'whitespace-pre-wrap font-body-sm';
        content.textContent = text;

        bubble.appendChild(senderRow);
        bubble.appendChild(content);

        const avatar = document.createElement('div');
        avatar.className = 'w-8 h-8 rounded-full bg-primary/20 flex items-center justify-center text-primary shrink-0 border border-primary/30';
        const icon = document.createElement('span');
        icon.className = 'material-symbols-outlined text-[18px]';
        icon.textContent = 'person';
        avatar.appendChild(icon);

        row.appendChild(bubble);
        row.appendChild(avatar);
        copilotChatFeed.appendChild(row);
    }

    function appendCopilotThinkingBubble() {
        const row = document.createElement('div');
        row.id = 'copilot-thinking-bubble';
        row.className = 'flex items-start gap-3';

        const avatar = document.createElement('div');
        avatar.className = 'w-8 h-8 rounded-full bg-primary/10 border border-primary/30 flex items-center justify-center text-primary shrink-0';
        const icon = document.createElement('span');
        icon.className = 'material-symbols-outlined text-[18px]';
        icon.textContent = 'smart_toy';
        avatar.appendChild(icon);

        const bubble = document.createElement('div');
        bubble.className = 'max-w-[85%] rounded-lg p-3 bg-surface-container-low border border-outline-variant text-xs text-on-surface-variant flex items-center gap-2';

        const spinner = document.createElement('span');
        spinner.className = 'btn-spinner';
        spinner.setAttribute('aria-hidden', 'true');

        const span = document.createElement('span');
        span.textContent = 'Copilot is formulating response & safety plan...';

        bubble.appendChild(spinner);
        bubble.appendChild(span);

        row.appendChild(avatar);
        row.appendChild(bubble);
        copilotChatFeed.appendChild(row);
        return row;
    }

    function appendCopilotErrorMessage(msg) {
        if (!copilotChatFeed) return;
        const row = document.createElement('div');
        row.className = 'flex items-start gap-3';

        const avatar = document.createElement('div');
        avatar.className = 'w-8 h-8 rounded-full bg-error/10 border border-error/30 flex items-center justify-center text-error shrink-0';
        const icon = document.createElement('span');
        icon.className = 'material-symbols-outlined text-[18px]';
        icon.textContent = 'error';
        avatar.appendChild(icon);

        const bubble = document.createElement('div');
        bubble.className = 'max-w-[85%] rounded-lg p-3 bg-error/10 border border-error/30 text-xs text-error leading-relaxed';
        bubble.textContent = msg;

        row.appendChild(avatar);
        row.appendChild(bubble);
        copilotChatFeed.appendChild(row);
    }

    function appendCopilotAssistantMessage(replyText, suggestedCommand) {
        if (!copilotChatFeed) return;
        const row = document.createElement('div');
        row.className = 'flex items-start gap-3';

        const avatar = document.createElement('div');
        avatar.className = 'w-8 h-8 rounded-full bg-primary/10 border border-primary/30 flex items-center justify-center text-primary shrink-0';
        const icon = document.createElement('span');
        icon.className = 'material-symbols-outlined text-[18px]';
        icon.textContent = 'smart_toy';
        avatar.appendChild(icon);

        const wrapper = document.createElement('div');
        wrapper.className = 'max-w-[85%] space-y-3';

        // 1. Text Message Bubble
        const bubble = document.createElement('div');
        bubble.className = 'rounded-lg p-3.5 bg-surface-container-low border border-outline-variant text-xs text-on-surface leading-relaxed space-y-2';

        const senderRow = document.createElement('div');
        senderRow.className = 'font-bold text-[10px] text-primary flex items-center gap-1.5 uppercase tracking-wider font-label-sm';
        const botIcon = document.createElement('span');
        botIcon.className = 'material-symbols-outlined text-[14px]';
        botIcon.textContent = 'verified_user';
        const nameSpan = document.createElement('span');
        nameSpan.textContent = 'Aegis Copilot';
        senderRow.appendChild(botIcon);
        senderRow.appendChild(nameSpan);
        bubble.appendChild(senderRow);

        // Render paragraphs cleanly using textContent
        const paragraphs = (replyText || '').split(/\n\n+/);
        paragraphs.forEach(para => {
            const p = document.createElement('p');
            p.className = 'whitespace-pre-wrap leading-relaxed';
            p.textContent = para.trim();
            bubble.appendChild(p);
        });

        wrapper.appendChild(bubble);

        // 2. Command Proposal Card (if command was suggested)
        if (suggestedCommand && suggestedCommand.command_string) {
            const cmdCard = buildCommandCard(suggestedCommand);
            wrapper.appendChild(cmdCard);
        }

        row.appendChild(avatar);
        row.appendChild(wrapper);
        copilotChatFeed.appendChild(row);
    }

    function buildCommandCard(cmd) {
        const card = document.createElement('div');
        card.className = 'p-4 rounded-lg bg-surface-container-lowest border border-primary/40 shadow-sm space-y-3';

        // Header: Tool badge, operation badge, title
        const header = document.createElement('div');
        header.className = 'flex items-center justify-between flex-wrap gap-2 pb-2 border-b border-outline-variant';

        const leftHeader = document.createElement('div');
        leftHeader.className = 'flex items-center gap-2';
        
        const toolBadge = document.createElement('span');
        toolBadge.className = 'px-2 py-0.5 rounded text-[10px] font-bold bg-primary text-on-primary font-code tracking-wider';
        toolBadge.textContent = (cmd.tool || 'NMAP').toUpperCase();

        const opBadge = document.createElement('span');
        opBadge.className = 'px-2 py-0.5 rounded text-[10px] font-bold bg-surface-container-high text-on-surface-variant font-code';
        opBadge.textContent = cmd.operation || 'custom_op';

        leftHeader.appendChild(toolBadge);
        leftHeader.appendChild(opBadge);

        const statusTag = document.createElement('span');
        statusTag.className = 'text-[11px] font-semibold text-primary flex items-center gap-1';
        const verifiedIcon = document.createElement('span');
        verifiedIcon.className = 'material-symbols-outlined text-[14px]';
        verifiedIcon.textContent = 'check_circle';
        const verifiedText = document.createElement('span');
        verifiedText.textContent = 'Validated Safe Plan';
        statusTag.appendChild(verifiedIcon);
        statusTag.appendChild(verifiedText);

        header.appendChild(leftHeader);
        header.appendChild(statusTag);
        card.appendChild(header);

        // Purpose
        const purposeP = document.createElement('p');
        purposeP.className = 'text-xs text-on-surface font-semibold';
        purposeP.textContent = cmd.purpose || 'Execute security diagnostic on authorized host.';
        card.appendChild(purposeP);

        // Command display box with copy button
        const cmdContainer = document.createElement('div');
        cmdContainer.className = 'relative flex items-center';

        const pre = document.createElement('pre');
        pre.className = 'w-full p-2.5 rounded bg-black/70 border border-outline-variant font-code text-xs text-primary overflow-x-auto whitespace-pre-wrap select-all';
        pre.textContent = cmd.command_string;

        const copyBtn = document.createElement('button');
        copyBtn.type = 'button';
        copyBtn.className = 'absolute right-2 top-2 p-1 rounded bg-surface-container border border-outline-variant text-on-surface-variant hover:text-on-surface text-xs flex items-center gap-1 cursor-pointer';
        copyBtn.setAttribute('title', 'Copy Command');
        const copyIcon = document.createElement('span');
        copyIcon.className = 'material-symbols-outlined text-[14px]';
        copyIcon.textContent = 'content_copy';
        copyBtn.appendChild(copyIcon);
        copyBtn.addEventListener('click', () => {
            navigator.clipboard.writeText(cmd.command_string).then(() => {
                showToast('Command copied to clipboard.', 'success');
            }).catch(() => {
                showToast('Unable to access clipboard.', 'info');
            });
        });

        cmdContainer.appendChild(pre);
        cmdContainer.appendChild(copyBtn);
        card.appendChild(cmdContainer);

        // Flag Explanations Breakdown
        if (cmd.arguments_breakdown && Object.keys(cmd.arguments_breakdown).length > 0) {
            const flagsBox = document.createElement('div');
            flagsBox.className = 'p-2.5 rounded bg-surface-container-low border border-outline-variant space-y-1.5';
            
            const flagsTitle = document.createElement('div');
            flagsTitle.className = 'text-[11px] font-bold text-on-surface-variant uppercase tracking-wider flex items-center gap-1';
            const flagIcon = document.createElement('span');
            flagIcon.className = 'material-symbols-outlined text-[13px]';
            flagIcon.textContent = 'tune';
            const flagTitleText = document.createElement('span');
            flagTitleText.textContent = 'Arguments Breakdown';
            flagsTitle.appendChild(flagIcon);
            flagsTitle.appendChild(flagTitleText);
            flagsBox.appendChild(flagsTitle);

            const grid = document.createElement('div');
            grid.className = 'grid grid-cols-1 sm:grid-cols-2 gap-1.5 text-[11px]';

            Object.entries(cmd.arguments_breakdown).forEach(([flag, desc]) => {
                const item = document.createElement('div');
                item.className = 'flex items-start gap-1.5';
                const fSpan = document.createElement('code');
                fSpan.className = 'px-1 rounded bg-surface-container-highest font-code text-primary font-bold shrink-0';
                fSpan.textContent = flag;
                const dSpan = document.createElement('span');
                dSpan.className = 'text-on-surface-variant leading-tight';
                dSpan.textContent = desc;
                item.appendChild(fSpan);
                item.appendChild(dSpan);
                grid.appendChild(item);
            });
            flagsBox.appendChild(grid);
            card.appendChild(flagsBox);
        }

        // Operational Considerations & Warnings
        const metaGrid = document.createElement('div');
        metaGrid.className = 'grid grid-cols-1 md:grid-cols-2 gap-2 text-[11px] text-on-surface-variant';

        if (cmd.performance_considerations) {
            const perfDiv = document.createElement('div');
            perfDiv.className = 'p-2 rounded bg-surface-container-low border border-outline-variant';
            const title = document.createElement('span');
            title.className = 'font-bold text-on-surface block mb-0.5';
            title.textContent = '⚡ Performance:';
            const body = document.createElement('span');
            body.textContent = cmd.performance_considerations;
            perfDiv.appendChild(title);
            perfDiv.appendChild(body);
            metaGrid.appendChild(perfDiv);
        }

        if (cmd.safety_warning) {
            const warnDiv = document.createElement('div');
            warnDiv.className = 'p-2 rounded bg-amber-500/10 border border-amber-500/30 text-amber-900 dark:text-amber-200';
            const title = document.createElement('span');
            title.className = 'font-bold text-amber-800 dark:text-amber-300 block mb-0.5 flex items-center gap-1';
            const warnIcon = document.createElement('span');
            warnIcon.className = 'material-symbols-outlined text-[13px]';
            warnIcon.textContent = 'warning';
            const warnLabel = document.createElement('span');
            warnLabel.textContent = 'Safety & Scope:';
            title.appendChild(warnIcon);
            title.appendChild(warnLabel);
            const body = document.createElement('span');
            body.className = 'text-[11px] text-on-surface-variant';
            body.textContent = cmd.safety_warning;
            warnDiv.appendChild(title);
            warnDiv.appendChild(body);
            metaGrid.appendChild(warnDiv);
        }

        card.appendChild(metaGrid);

        // Action Footer: Run Command Button
        const actionsRow = document.createElement('div');
        actionsRow.className = 'pt-2 border-t border-outline-variant flex items-center justify-between flex-wrap gap-2';

        const targetNote = document.createElement('span');
        targetNote.className = 'text-[11px] text-on-surface-variant font-code';
        targetNote.textContent = `Target: ${cmd.target} (shell=False execution)`;

        const runBtn = document.createElement('button');
        runBtn.type = 'button';
        runBtn.className = 'btn btn-primary px-4 py-2 rounded bg-primary text-on-primary font-semibold text-xs hover:bg-primary-fixed-dim transition-colors flex items-center gap-1.5 cursor-pointer shadow-sm';
        const playIcon = document.createElement('span');
        playIcon.className = 'material-symbols-outlined text-[16px]';
        playIcon.textContent = 'play_arrow';
        const btnText = document.createElement('span');
        btnText.textContent = 'Run Command';
        runBtn.appendChild(playIcon);
        runBtn.appendChild(btnText);

        runBtn.addEventListener('click', () => {
            promptCommandExecution(cmd, runBtn, card);
        });

        actionsRow.appendChild(targetNote);
        actionsRow.appendChild(runBtn);
        card.appendChild(actionsRow);

        return card;
    }

    // =========================================================================
    // EXECUTION MODAL & RUNNER WORKFLOW
    // =========================================================================
    let activeCardRunBtn = null;
    let activeCommandCard = null;

    function promptCommandExecution(plan, runBtn, card) {
        pendingExecutionPlan = plan;
        activeCardRunBtn = runBtn;
        activeCommandCard = card;

        if (copilotModalTarget) copilotModalTarget.textContent = plan.target || copilotActiveTarget;
        if (copilotModalOperation) copilotModalOperation.textContent = plan.operation || 'ad_hoc';
        if (copilotModalCommand) copilotModalCommand.textContent = plan.command_string;
        if (copilotModalWarning) {
            copilotModalWarning.textContent = plan.safety_warning || 'Active network probing generates live packets. Ensure target is authorized.';
        }
        if (copilotModalAuthCheck) copilotModalAuthCheck.checked = false;
        if (copilotModalExecuteBtn) copilotModalExecuteBtn.disabled = true;

        showElement(copilotConfirmModal);
    }

    if (copilotModalAuthCheck) {
        copilotModalAuthCheck.addEventListener('change', () => {
            if (copilotModalExecuteBtn) {
                copilotModalExecuteBtn.disabled = !copilotModalAuthCheck.checked;
            }
        });
    }

    function closeCopilotModal() {
        hideElement(copilotConfirmModal);
        pendingExecutionPlan = null;
    }

    if (copilotModalClose) copilotModalClose.addEventListener('click', closeCopilotModal);
    if (copilotModalCancelBtn) copilotModalCancelBtn.addEventListener('click', closeCopilotModal);
    if (copilotConfirmModal) {
        copilotConfirmModal.addEventListener('click', (e) => {
            if (e.target === copilotConfirmModal) closeCopilotModal();
        });
    }

    if (copilotModalExecuteBtn) {
        copilotModalExecuteBtn.addEventListener('click', async () => {
            if (!pendingExecutionPlan) return;
            const planToRun = pendingExecutionPlan;
            closeCopilotModal();

            if (activeCardRunBtn) {
                activeCardRunBtn.disabled = true;
                activeCardRunBtn.innerHTML = '';
                const spinner = document.createElement('span');
                spinner.className = 'btn-spinner';
                const label = document.createElement('span');
                label.textContent = 'Running...';
                activeCardRunBtn.appendChild(spinner);
                activeCardRunBtn.appendChild(label);
            }

            setCopilotStatus('EXECUTING...', 'executing');

            // Append live execution drawer into chat feed
            const execDrawer = buildExecutionDrawer(planToRun);
            if (copilotChatFeed) copilotChatFeed.appendChild(execDrawer.container);
            scrollChatToBottom();

            try {
                const res = await fetch('/api/copilot/execute', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        conversation_id: copilotConversationId,
                        execution_plan: planToRun,
                        confirmed: true,
                        scan_id: copilotActiveScanId
                    })
                });

                const data = await res.json();
                if (!res.ok || data.status === 'error') {
                    execDrawer.markStatus('ERROR', 'error');
                    execDrawer.appendOutput(`\n[Execution Error]: ${data.message || 'Server rejected execution plan.'}\n`);
                    setCopilotStatus('READY', 'ready');
                    if (activeCardRunBtn) {
                        activeCardRunBtn.disabled = false;
                        activeCardRunBtn.textContent = 'Run Command';
                    }
                    showToast(data.message || 'Execution error.', 'error');
                    return;
                }

                const executionId = data.execution_id;
                pollExecutionProgress(executionId, execDrawer, planToRun);

            } catch (err) {
                execDrawer.markStatus('ERROR', 'error');
                execDrawer.appendOutput(`\n[Connection Error]: Failed to contact execution runner.\n`);
                setCopilotStatus('READY', 'ready');
                if (activeCardRunBtn) {
                    activeCardRunBtn.disabled = false;
                    activeCardRunBtn.textContent = 'Run Command';
                }
                showToast('Failed to start command execution.', 'error');
            }
        });
    }

    function buildExecutionDrawer(plan) {
        const container = document.createElement('div');
        container.className = 'p-4 rounded-lg bg-surface-container border border-outline-variant shadow-md space-y-3';

        // Header
        const header = document.createElement('div');
        header.className = 'flex items-center justify-between flex-wrap gap-2 pb-2 border-b border-outline-variant';

        const titleDiv = document.createElement('div');
        titleDiv.className = 'flex items-center gap-2 font-code text-xs font-bold text-on-surface';
        const termIcon = document.createElement('span');
        termIcon.className = 'material-symbols-outlined text-primary text-[18px]';
        termIcon.textContent = 'terminal';
        const titleSpan = document.createElement('span');
        titleSpan.textContent = `Running: ${plan.operation}`;
        titleDiv.appendChild(termIcon);
        titleDiv.appendChild(titleSpan);

        const rightControls = document.createElement('div');
        rightControls.className = 'flex items-center gap-2';

        const statusBadge = document.createElement('span');
        statusBadge.className = 'px-2 py-0.5 rounded text-[10px] font-bold border border-primary/30 bg-primary/10 text-primary animate-pulse';
        statusBadge.textContent = 'RUNNING';

        const cancelBtn = document.createElement('button');
        cancelBtn.type = 'button';
        cancelBtn.className = 'px-2 py-1 rounded bg-surface-container-high border border-outline-variant text-error hover:bg-error/10 text-xs font-semibold flex items-center gap-1 cursor-pointer';
        const cancelIcon = document.createElement('span');
        cancelIcon.className = 'material-symbols-outlined text-[13px]';
        cancelIcon.textContent = 'stop_circle';
        const cancelText = document.createElement('span');
        cancelText.textContent = 'Cancel';
        cancelBtn.appendChild(cancelIcon);
        cancelBtn.appendChild(cancelText);

        rightControls.appendChild(statusBadge);
        rightControls.appendChild(cancelBtn);

        header.appendChild(titleDiv);
        header.appendChild(rightControls);
        container.appendChild(header);

        // Command display line
        const cmdLine = document.createElement('div');
        cmdLine.className = 'text-[11px] font-code text-on-surface-variant';
        cmdLine.textContent = `$ ${plan.command_string}`;
        container.appendChild(cmdLine);

        // Terminal Console Box
        const terminalBox = document.createElement('pre');
        terminalBox.className = 'p-3 rounded bg-black/90 border border-outline-variant font-code text-[11px] text-green-400 max-h-56 overflow-y-auto whitespace-pre-wrap leading-tight';
        terminalBox.textContent = `[Aegis Runner] Spawning process (shell=False, timeout=${plan.timeout || 120}s)...\n`;
        container.appendChild(terminalBox);

        // Live Findings / AI Analysis container (initially hidden)
        const analysisContainer = document.createElement('div');
        analysisContainer.className = 'hidden space-y-3 pt-2 border-t border-outline-variant';
        container.appendChild(analysisContainer);

        return {
            container,
            terminalBox,
            statusBadge,
            cancelBtn,
            analysisContainer,
            markStatus: (text, type) => {
                statusBadge.textContent = text;
                statusBadge.classList.remove('animate-pulse');
                if (type === 'success') {
                    statusBadge.className = 'px-2 py-0.5 rounded text-[10px] font-bold border border-green-500/30 bg-green-500/10 text-green-500';
                } else if (type === 'error') {
                    statusBadge.className = 'px-2 py-0.5 rounded text-[10px] font-bold border border-error/30 bg-error/10 text-error';
                } else if (type === 'cancelled') {
                    statusBadge.className = 'px-2 py-0.5 rounded text-[10px] font-bold border border-amber-500/30 bg-amber-500/10 text-amber-800 dark:text-amber-300';
                }
            },
            appendOutput: (chunk) => {
                if (chunk) {
                    terminalBox.textContent += chunk;
                    terminalBox.scrollTop = terminalBox.scrollHeight;
                }
            },
            setOutput: (text) => {
                terminalBox.textContent = text;
                terminalBox.scrollTop = terminalBox.scrollHeight;
            }
        };
    }

    function pollExecutionProgress(executionId, drawer, plan) {
        let isCompleted = false;

        drawer.cancelBtn.addEventListener('click', async () => {
            drawer.cancelBtn.disabled = true;
            drawer.cancelBtn.textContent = 'Cancelling...';
            try {
                await fetch(`/api/copilot/execution/${executionId}/cancel`, { method: 'POST' });
                showToast('Sent cancellation request to runner.', 'info');
            } catch (_) {}
        });

        const pollTimer = setInterval(async () => {
            if (isCompleted) {
                clearInterval(pollTimer);
                return;
            }

            try {
                const res = await fetch(`/api/copilot/execution/${executionId}`);
                if (!res.ok) return;

                const exec = await res.json();
                if (exec.raw_output) {
                    drawer.setOutput(exec.raw_output);
                }

                if (exec.status === 'completed') {
                    isCompleted = true;
                    clearInterval(pollTimer);
                    drawer.markStatus('COMPLETED', 'success');
                    drawer.cancelBtn.classList.add('hidden');
                    setCopilotStatus('READY', 'ready');

                    if (activeCardRunBtn) {
                        activeCardRunBtn.disabled = false;
                        activeCardRunBtn.innerHTML = '';
                        const checkIcon = document.createElement('span');
                        checkIcon.className = 'material-symbols-outlined text-[16px] text-green-400';
                        checkIcon.textContent = 'check';
                        const checkSpan = document.createElement('span');
                        checkSpan.textContent = 'Executed';
                        activeCardRunBtn.appendChild(checkIcon);
                        activeCardRunBtn.appendChild(checkSpan);
                    }

                    // Render Parsed Findings & AI Live Analysis
                    renderExecutionResults(drawer.analysisContainer, exec);
                    showToast(`Command execution completed (${exec.execution_time_seconds || 0}s). Findings logged.`, 'success');
                    scrollChatToBottom();

                } else if (exec.status === 'cancelled') {
                    isCompleted = true;
                    clearInterval(pollTimer);
                    drawer.markStatus('CANCELLED', 'cancelled');
                    drawer.cancelBtn.classList.add('hidden');
                    setCopilotStatus('READY', 'ready');
                    if (activeCardRunBtn) {
                        activeCardRunBtn.disabled = false;
                        activeCardRunBtn.textContent = 'Run Command';
                    }
                    showToast('Command execution was cancelled.', 'info');

                } else if (exec.status === 'error' || exec.status === 'timeout') {
                    isCompleted = true;
                    clearInterval(pollTimer);
                    drawer.markStatus(exec.status === 'timeout' ? 'TIMEOUT' : 'ERROR', 'error');
                    drawer.cancelBtn.classList.add('hidden');
                    setCopilotStatus('READY', 'ready');
                    if (activeCardRunBtn) {
                        activeCardRunBtn.disabled = false;
                        activeCardRunBtn.textContent = 'Run Command';
                    }
                    showToast(`Execution ended with status: ${exec.status}`, 'error');
                }

            } catch (pollErr) {
                // Non-fatal transient poll error
            }
        }, 1200);
    }

    function renderExecutionResults(container, exec) {
        if (!container) return;
        container.innerHTML = '';
        showElement(container);

        // 1. Parsed Findings Box
        const findingsBox = document.createElement('div');
        findingsBox.className = 'p-3 rounded bg-surface-container-low border border-outline-variant space-y-2';

        const findingsTitle = document.createElement('div');
        findingsTitle.className = 'flex items-center gap-2 font-bold text-xs text-on-surface uppercase tracking-wider font-label-sm';
        const fIcon = document.createElement('span');
        fIcon.className = 'material-symbols-outlined text-primary text-[16px]';
        fIcon.textContent = 'data_exploration';
        const fTitle = document.createElement('span');
        fTitle.textContent = 'Extracted Audit Findings';
        findingsTitle.appendChild(fIcon);
        findingsTitle.appendChild(fTitle);
        findingsBox.appendChild(findingsTitle);

        const findings = exec.parsed_findings || {};
        if (findings.open_ports && findings.open_ports.length > 0) {
            const portsList = document.createElement('div');
            portsList.className = 'flex flex-wrap gap-1.5';
            findings.open_ports.forEach(p => {
                const badge = document.createElement('span');
                const risk = (p.risk || 'low').toLowerCase();
                const riskColor = risk === 'high' ? 'bg-error/15 text-error border-error/30' : (risk === 'medium' ? 'bg-tertiary-container/15 text-tertiary-container border-tertiary-container/30' : 'bg-primary/15 text-primary border-primary/30');
                badge.className = `px-2 py-0.5 rounded font-code text-xs border ${riskColor} flex items-center gap-1`;
                badge.textContent = `Port ${p.port}/${p.protocol || 'tcp'}: ${p.service || 'unknown'} (${(p.risk || 'LOW').toUpperCase()})`;
                portsList.appendChild(badge);
            });
            findingsBox.appendChild(portsList);
        } else if (findings.web_observation) {
            const obs = findings.web_observation;
            const obsDiv = document.createElement('div');
            obsDiv.className = 'text-xs text-on-surface-variant font-code space-y-1';
            
            const line1 = document.createElement('div');
            line1.textContent = `Status: ${obs.status_code || 'N/A'} | Server: ${obs.server_header || 'Unknown'} | Title: ${obs.html_title || 'None'}`;
            obsDiv.appendChild(line1);

            if (obs.tls_certificate) {
                const line2 = document.createElement('div');
                line2.textContent = `TLS Subject: ${obs.tls_certificate.subject_common_name || 'N/A'} (Expires: ${obs.tls_certificate.valid_until || 'N/A'})`;
                obsDiv.appendChild(line2);
            }
            findingsBox.appendChild(obsDiv);
        } else if (findings.reverse_dns) {
            const dnsDiv = document.createElement('div');
            dnsDiv.className = 'text-xs text-on-surface font-code';
            dnsDiv.textContent = `Canonical Hostname: ${findings.reverse_dns.primary_hostname || 'None resolved'}`;
            findingsBox.appendChild(dnsDiv);
        } else {
            const emptyP = document.createElement('p');
            emptyP.className = 'text-xs text-on-surface-variant';
            emptyP.textContent = 'Command executed cleanly. No discrete open ports or service endpoints were discovered in output.';
            findingsBox.appendChild(emptyP);
        }

        container.appendChild(findingsBox);

        // 2. Automated AI Analysis Explanation
        if (exec.ai_analysis && exec.ai_analysis.explanation) {
            const aiBox = document.createElement('div');
            aiBox.className = 'p-3.5 rounded bg-surface-container-low border border-primary/30 space-y-2.5';

            const aiHeader = document.createElement('div');
            aiHeader.className = 'flex items-center justify-between flex-wrap gap-2';

            const leftAi = document.createElement('div');
            leftAi.className = 'flex items-center gap-1.5 font-bold text-xs text-primary font-label-sm';
            const aiIcon = document.createElement('span');
            aiIcon.className = 'material-symbols-outlined text-[16px]';
            aiIcon.textContent = 'psychology';
            const aiTitle = document.createElement('span');
            aiTitle.textContent = 'AI Security Analyst — Live Interpretation';
            leftAi.appendChild(aiIcon);
            leftAi.appendChild(aiTitle);

            const confBadge = document.createElement('span');
            confBadge.className = 'px-1.5 py-0.5 rounded text-[10px] font-bold font-code bg-primary/10 text-primary border border-primary/30';
            confBadge.textContent = `Confidence: ${(exec.ai_analysis.confidence || 'HIGH').toUpperCase()}`;

            aiHeader.appendChild(leftAi);
            aiHeader.appendChild(confBadge);
            aiBox.appendChild(aiHeader);

            // Observation & Explanation
            const expP = document.createElement('p');
            expP.className = 'text-xs text-on-surface leading-relaxed';
            expP.textContent = exec.ai_analysis.explanation;
            aiBox.appendChild(expP);

            // Recommendations / Next Steps
            if (exec.ai_analysis.recommendations && exec.ai_analysis.recommendations.length > 0) {
                const recDiv = document.createElement('div');
                recDiv.className = 'pt-1.5 border-t border-outline-variant space-y-1';
                const recTitle = document.createElement('span');
                recTitle.className = 'text-[11px] font-bold text-tertiary-container uppercase tracking-wider block font-label-sm';
                recTitle.textContent = 'Recommended Next Steps:';
                recDiv.appendChild(recTitle);

                const list = document.createElement('ul');
                list.className = 'list-disc pl-4 text-xs text-on-surface-variant space-y-0.5';
                exec.ai_analysis.recommendations.forEach(r => {
                    const li = document.createElement('li');
                    li.textContent = r;
                    list.appendChild(li);
                });
                recDiv.appendChild(list);
                aiBox.appendChild(recDiv);
            }

            container.appendChild(aiBox);
        }

        // 3. Export Integration Notice
        const exportNotice = document.createElement('div');
        exportNotice.className = 'p-2 rounded bg-surface-container-lowest border border-outline-variant text-[11px] text-on-surface-variant flex items-center justify-between flex-wrap gap-2';
        const noticeLeft = document.createElement('span');
        noticeLeft.className = 'flex items-center gap-1.5';
        const nIcon = document.createElement('span');
        nIcon.className = 'material-symbols-outlined text-[14px] text-primary';
        nIcon.textContent = 'sync_saved_locally';
        const nText = document.createElement('span');
        nText.textContent = 'Command audit results automatically integrated into PDF, CSV, JSON, and TXT exports.';
        noticeLeft.appendChild(nIcon);
        noticeLeft.appendChild(nText);
        exportNotice.appendChild(noticeLeft);

        container.appendChild(exportNotice);
    }

    // =========================================================================
    // ERROR & TOAST CONTROLLER
    // =========================================================================
    function showError(message) {
        if (errorMessage) errorMessage.textContent = message;
        showElement(errorContainer);
        if (errorContainer) {
            errorContainer.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }
    }

    function showToast(message, type = 'info') {
        if (!toastContainer) return;
        const toast = document.createElement('div');
        toast.className = `toast toast-${type} p-3 rounded bg-surface-container border flex items-center gap-2 shadow-lg transition-all duration-300 max-w-sm pointer-events-auto`;
        
        // Inline icons based on type
        const iconSpan = document.createElement('span');
        iconSpan.className = 'material-symbols-outlined text-[16px]';
        if (type === 'success') {
            iconSpan.classList.add('text-green-500');
            iconSpan.textContent = 'check_circle';
        } else if (type === 'error') {
            iconSpan.classList.add('text-error');
            iconSpan.textContent = 'warning';
        } else {
            iconSpan.classList.add('text-primary');
            iconSpan.textContent = 'info';
        }
        
        const textSpan = document.createElement('span');
        textSpan.className = 'text-body-sm text-on-surface';
        textSpan.textContent = message;

        toast.appendChild(iconSpan);
        toast.appendChild(textSpan);
        toastContainer.appendChild(toast);

        // Fade out
        setTimeout(() => {
            toast.style.opacity = '0';
            setTimeout(() => toast.remove(), 300);
        }, 3800);
    }

    function showElement(el) {
        if (el) el.classList.remove('hidden');
    }

    function hideElement(el) {
        if (el) el.classList.add('hidden');
    }
});
