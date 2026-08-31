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
        reports: document.getElementById('nav-link-reports'),
        settings: document.getElementById('nav-link-settings')
    };

    const views = {
        dashboard: document.getElementById('view-dashboard'),
        newScan: document.getElementById('view-new-scan'),
        results: document.getElementById('view-scan-results'),
        history: document.getElementById('view-history'),
        reports: document.getElementById('view-reports'),
        settings: document.getElementById('view-settings')
    };

    const sidebarInitiateScan = document.getElementById('sidebar-initiate-scan');
    const headerSettingsBtn = document.getElementById('header-settings-btn');
    const viewAllLogsBtn = document.getElementById('view-all-logs-btn');

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
                if (k === viewName) {
                    navLinks[k].className = 'w-full flex items-center gap-3 px-4 py-2 border-l-2 border-primary bg-secondary-container text-on-secondary-container transition-all';
                } else {
                    navLinks[k].className = 'w-full flex items-center gap-3 px-4 py-2 text-on-surface-variant hover:bg-surface-container-highest transition-colors';
                }
            }
        });

        // Trigger automatic loads
        if (viewName === 'dashboard' || viewName === 'history' || viewName === 'reports') {
            loadDashboardData();
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
    const resultPortsCount = document.getElementById('result-ports-count');
    const resultOverallRisk = document.getElementById('result-overall-risk');
    const resultStatus = document.getElementById('result-status');
    const resultBreakdownText = document.getElementById('result-breakdown-text');
    const resultsTableWrapper = document.getElementById('results-table-wrapper');
    const resultsTableBody = document.getElementById('results-table-body');
    const emptyPortsMessage = document.getElementById('empty-ports-message');
    const exportReportLink = document.getElementById('export-report-link');

    const historyTableWrapper = document.getElementById('history-table-wrapper');
    const historyTableBody = document.getElementById('history-table-body');
    const emptyHistoryBox = document.getElementById('empty-history-box');
    const clearHistoryBtn = document.getElementById('clear-history-btn');

    const confirmModal = document.getElementById('confirm-modal');
    const modalCancelBtn = document.getElementById('modal-cancel-btn');
    const modalConfirmBtn = document.getElementById('modal-confirm-btn');
    const toastContainer = document.getElementById('toast-container');

    const quickTags = document.querySelectorAll('.quick-tag');

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
            executeScan(quickTargetInput.value.trim());
        });
    }

    async function executeScan(target) {
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
                body: JSON.stringify({ target: target })
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

        if (data.scan_id) {
            exportReportLink.href = `/api/scan/${data.scan_id}/export`;
            showElement(exportReportLink);
        } else {
            hideElement(exportReportLink);
        }

        switchView('results');
    }

    // =========================================================================
    // LOAD STATISTICS AND PERSISTED RUNS
    // =========================================================================
    async function loadDashboardData() {
        try {
            const [statsRes, historyRes] = await Promise.all([
                fetch('/api/stats'),
                fetch('/api/history')
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
            tdAction.className = 'p-3 text-right';
            const downloadBtn = document.createElement('a');
            downloadBtn.href = `/api/scan/${scan.id}/export`;
            downloadBtn.className = 'text-primary hover:text-primary-container p-1 rounded hover:bg-surface-container inline-block';
            downloadBtn.setAttribute('download', '');
            
            const downloadIcon = document.createElement('span');
            downloadIcon.className = 'material-symbols-outlined text-[18px]';
            downloadIcon.textContent = 'download';
            downloadBtn.appendChild(downloadIcon);
            tdAction.appendChild(downloadBtn);

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
        if (e.key === 'Escape' && confirmModal && !confirmModal.classList.contains('hidden')) {
            hideElement(confirmModal);
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

    if (exportTextBtn) {
        exportTextBtn.addEventListener('click', () => {
            // Export the latest scan from the page if visible or download all text reports
            showToast('Initiating raw technical text log file download...', 'info');
            window.location.href = '/api/history';
        });
    }

    if (exportJsonBtn) {
        exportJsonBtn.addEventListener('click', () => {
            showToast('Initiating JSON findings payload dump...', 'info');
            window.location.href = '/api/stats';
        });
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
