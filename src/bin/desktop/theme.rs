//! Terminal-style theme for FragglePacket Desktop
//!
//! Retro green-on-black aesthetic matching the TUI.

pub fn get_css() -> &'static str {
    r#"
:root {
    --term-green: #00FF41;
    --term-green-dim: #00B42D;
    --term-green-dark: #006419;
    --term-amber: #FFB000;
    --term-red: #FF3232;
    --term-black: #050F05;
    --term-cyan: #00FFC8;

    --font-mono: "SF Mono", "JetBrains Mono", "Fira Code", "Consolas", monospace;
    --font-size-sm: 12px;
    --font-size-md: 14px;
    --font-size-lg: 18px;
    --font-size-xl: 24px;

    --spacing-xs: 4px;
    --spacing-sm: 8px;
    --spacing-md: 16px;
    --spacing-lg: 24px;
    --spacing-xl: 32px;

    --radius-sm: 4px;
    --radius-md: 8px;
}

* {
    box-sizing: border-box;
    margin: 0;
    padding: 0;
}

body {
    font-family: var(--font-mono);
    font-size: var(--font-size-md);
    background-color: var(--term-black);
    color: var(--term-green);
    line-height: 1.5;
    overflow: hidden;
}

/* Layout */
.app-container {
    display: flex;
    flex-direction: column;
    height: 100vh;
    width: 100vw;
}

.header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: var(--spacing-sm) var(--spacing-md);
    border-bottom: 1px solid var(--term-green-dark);
    background: linear-gradient(180deg, rgba(0, 255, 65, 0.1) 0%, transparent 100%);
}

.header h1 {
    font-size: var(--font-size-lg);
    font-weight: 600;
    color: var(--term-green);
    text-shadow: 0 0 10px var(--term-green);
}

.header .status {
    font-size: var(--font-size-sm);
    color: var(--term-green-dim);
}

/* Tabs */
.tabs {
    display: flex;
    gap: var(--spacing-xs);
    padding: var(--spacing-xs) var(--spacing-md);
    border-bottom: 1px solid var(--term-green-dark);
    background-color: rgba(0, 0, 0, 0.3);
}

.tab {
    padding: var(--spacing-sm) var(--spacing-md);
    border: 1px solid transparent;
    border-radius: var(--radius-sm) var(--radius-sm) 0 0;
    background: transparent;
    color: var(--term-green-dim);
    cursor: pointer;
    font-family: var(--font-mono);
    font-size: var(--font-size-sm);
    transition: all 0.2s ease;
}

.tab:hover {
    color: var(--term-green);
    border-color: var(--term-green-dark);
    background-color: rgba(0, 255, 65, 0.05);
}

.tab.active {
    color: var(--term-green);
    border-color: var(--term-green-dark);
    border-bottom-color: var(--term-black);
    background-color: var(--term-black);
}

/* Content Area */
.content {
    flex: 1;
    overflow: auto;
    padding: var(--spacing-md);
}

/* Panels */
.panel {
    border: 1px solid var(--term-green-dark);
    border-radius: var(--radius-md);
    padding: var(--spacing-md);
    margin-bottom: var(--spacing-md);
    background-color: rgba(0, 255, 65, 0.02);
}

.panel-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: var(--spacing-md);
    padding-bottom: var(--spacing-sm);
    border-bottom: 1px solid var(--term-green-dark);
}

.panel-title {
    font-size: var(--font-size-md);
    font-weight: 600;
    color: var(--term-green);
}

/* Buttons */
.btn {
    padding: var(--spacing-sm) var(--spacing-md);
    border: 1px solid var(--term-green);
    border-radius: var(--radius-sm);
    background: transparent;
    color: var(--term-green);
    cursor: pointer;
    font-family: var(--font-mono);
    font-size: var(--font-size-sm);
    transition: all 0.2s ease;
}

.btn:hover {
    background-color: var(--term-green);
    color: var(--term-black);
    box-shadow: 0 0 10px var(--term-green);
}

.btn:active {
    transform: scale(0.98);
}

.btn.primary {
    background-color: var(--term-green);
    color: var(--term-black);
}

.btn.primary:hover {
    background-color: var(--term-cyan);
    border-color: var(--term-cyan);
}

.btn.danger {
    border-color: var(--term-red);
    color: var(--term-red);
}

.btn.danger:hover {
    background-color: var(--term-red);
    color: var(--term-black);
}

/* Tables */
.table {
    width: 100%;
    border-collapse: collapse;
    font-size: var(--font-size-sm);
}

.table th,
.table td {
    padding: var(--spacing-sm);
    text-align: left;
    border-bottom: 1px solid var(--term-green-dark);
}

.table th {
    color: var(--term-green);
    font-weight: 600;
    background-color: rgba(0, 255, 65, 0.1);
}

.table tr:hover {
    background-color: rgba(0, 255, 65, 0.05);
}

/* Status indicators */
.status-success { color: var(--term-green); }
.status-warning { color: var(--term-amber); }
.status-error { color: var(--term-red); }
.status-pending { color: var(--term-green-dim); }
.status-ready { color: var(--term-green-dim); opacity: 0.7; }

/* Category Grid */
.category-grid {
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: var(--spacing-sm);
    margin-bottom: var(--spacing-md);
}

.category-btn {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: var(--spacing-md);
    border: 1px solid var(--term-green-dark);
    border-radius: var(--radius-md);
    background: transparent;
    color: var(--term-green-dim);
    cursor: pointer;
    font-family: var(--font-mono);
    transition: all 0.2s ease;
}

.category-btn:hover {
    border-color: var(--term-green);
    color: var(--term-green);
    background-color: rgba(0, 255, 65, 0.1);
}

.category-btn.selected {
    border-color: var(--term-green);
    color: var(--term-green);
    background-color: rgba(0, 255, 65, 0.15);
    box-shadow: 0 0 10px rgba(0, 255, 65, 0.3);
}

.category-btn .key {
    font-size: var(--font-size-xl);
    font-weight: bold;
    margin-bottom: var(--spacing-xs);
}

.category-btn .label {
    font-size: var(--font-size-sm);
}

/* Input fields */
input[type="text"],
input[type="number"],
select {
    padding: var(--spacing-sm);
    border: 1px solid var(--term-green-dark);
    border-radius: var(--radius-sm);
    background-color: var(--term-black);
    color: var(--term-green);
    font-family: var(--font-mono);
    font-size: var(--font-size-md);
}

input[type="text"]:focus,
input[type="number"]:focus,
select:focus {
    outline: none;
    border-color: var(--term-green);
    box-shadow: 0 0 5px rgba(0, 255, 65, 0.3);
}

/* Progress bar */
.progress-bar {
    width: 100%;
    height: 8px;
    background-color: var(--term-green-dark);
    border-radius: var(--radius-sm);
    overflow: hidden;
}

.progress-bar .fill {
    height: 100%;
    background-color: var(--term-green);
    transition: width 0.3s ease;
}

/* Waterfall chart */
.waterfall {
    display: flex;
    flex-direction: column;
    gap: var(--spacing-xs);
}

.waterfall-stage {
    display: flex;
    align-items: center;
    gap: var(--spacing-sm);
}

.waterfall-label {
    width: 100px;
    font-size: var(--font-size-sm);
    color: var(--term-green-dim);
}

.waterfall-bar {
    flex: 1;
    height: 24px;
    background-color: var(--term-green-dark);
    border-radius: var(--radius-sm);
    position: relative;
}

.waterfall-fill {
    height: 100%;
    background-color: var(--term-green);
    border-radius: var(--radius-sm);
    display: flex;
    align-items: center;
    justify-content: flex-end;
    padding-right: var(--spacing-sm);
    font-size: var(--font-size-sm);
    color: var(--term-black);
}

/* Scrollbar styling */
::-webkit-scrollbar {
    width: 8px;
    height: 8px;
}

::-webkit-scrollbar-track {
    background: var(--term-black);
}

::-webkit-scrollbar-thumb {
    background: var(--term-green-dark);
    border-radius: var(--radius-sm);
}

::-webkit-scrollbar-thumb:hover {
    background: var(--term-green-dim);
}

/* Detach button - positioned in header, not absolute */

/* Toast notifications */
.toast-container {
    position: fixed;
    bottom: var(--spacing-lg);
    right: var(--spacing-lg);
    display: flex;
    flex-direction: column;
    gap: var(--spacing-sm);
    z-index: 1000;
}

.toast {
    padding: var(--spacing-sm) var(--spacing-md);
    border-radius: var(--radius-sm);
    animation: slideIn 0.3s ease;
}

.toast.success {
    background-color: var(--term-green);
    color: var(--term-black);
}

.toast.warning {
    background-color: var(--term-amber);
    color: var(--term-black);
}

.toast.error {
    background-color: var(--term-red);
    color: var(--term-black);
}

@keyframes slideIn {
    from {
        transform: translateX(100%);
        opacity: 0;
    }
    to {
        transform: translateX(0);
        opacity: 1;
    }
}

/* Results Display */
.results-display {
    display: flex;
    flex-direction: column;
    gap: var(--spacing-md);
}

.result-card {
    border: 1px solid var(--term-green-dark);
    border-radius: var(--radius-md);
    padding: var(--spacing-md);
    background-color: rgba(0, 255, 65, 0.02);
}

.result-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: var(--spacing-sm);
}

.result-name {
    font-weight: 600;
    color: var(--term-green);
}

.result-status {
    padding: 2px 8px;
    border-radius: var(--radius-sm);
    font-size: var(--font-size-sm);
    font-weight: 600;
}

.result-target,
.result-duration {
    font-size: var(--font-size-sm);
    color: var(--term-green-dim);
    margin-bottom: var(--spacing-xs);
}

.result-metrics,
.result-metadata,
.result-diagnoses,
.result-visualization {
    margin-top: var(--spacing-md);
    padding-top: var(--spacing-sm);
    border-top: 1px solid var(--term-green-dark);
}

/* Visualization header */
.viz-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: var(--spacing-sm);
}

.viz-title {
    font-size: var(--font-size-sm);
    color: var(--term-green);
    font-weight: 600;
}

.viz-status {
    font-size: var(--font-size-sm);
    color: var(--term-green-dim);
}

/* Metrics grid for better layout */
.metrics-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
    gap: var(--spacing-xs) var(--spacing-md);
}

/* Hop table styling */
.hop-table {
    width: 100%;
    font-size: var(--font-size-sm);
}

.hop-table th {
    text-align: left;
    padding: var(--spacing-xs) var(--spacing-sm);
    color: var(--term-green-dim);
    border-bottom: 1px solid var(--term-green-dark);
}

.hop-table td {
    padding: var(--spacing-xs) var(--spacing-sm);
    border-bottom: 1px solid rgba(0, 255, 65, 0.1);
}

.hop-table .hop-addr {
    font-family: 'SF Mono', 'Menlo', monospace;
    color: var(--term-cyan);
}

.result-metrics h4,
.result-metadata h4,
.result-diagnoses h4 {
    font-size: var(--font-size-sm);
    color: var(--term-green);
    margin-bottom: var(--spacing-sm);
}

.metric,
.metadata {
    display: flex;
    gap: var(--spacing-sm);
    font-size: var(--font-size-sm);
    margin-bottom: var(--spacing-xs);
}

.metric-key,
.metadata-key {
    color: var(--term-green-dim);
}

.metric-value,
.metadata-value {
    color: var(--term-green);
}

/* Diagnosis styles */
.diagnosis {
    margin-bottom: var(--spacing-sm);
    padding: var(--spacing-sm);
    border-radius: var(--radius-sm);
    border-left: 3px solid var(--term-green);
}

.diagnosis-info {
    border-left-color: var(--term-green);
    background-color: rgba(0, 255, 65, 0.05);
}

.diagnosis-warning {
    border-left-color: var(--term-amber);
    background-color: rgba(255, 176, 0, 0.05);
}

.diagnosis-error,
.diagnosis-critical {
    border-left-color: var(--term-red);
    background-color: rgba(255, 50, 50, 0.05);
}

.diagnosis-title {
    font-weight: 600;
    margin-bottom: var(--spacing-xs);
}

.diagnosis-desc {
    font-size: var(--font-size-sm);
    color: var(--term-green-dim);
}

.diagnosis-recs {
    margin-top: var(--spacing-sm);
    font-size: var(--font-size-sm);
}

.diagnosis-recs ul {
    margin-top: var(--spacing-xs);
    padding-left: var(--spacing-md);
}

.diagnosis-recs li {
    margin-bottom: var(--spacing-xs);
    color: var(--term-green-dim);
}

/* No results placeholder */
.no-results {
    text-align: center;
    padding: var(--spacing-xl);
    color: var(--term-green-dim);
}

/* Stats */
.stat {
    text-align: center;
    padding: var(--spacing-md);
    border: 1px solid var(--term-green-dark);
    border-radius: var(--radius-md);
    background-color: rgba(0, 255, 65, 0.02);
}

.stat-value {
    font-size: var(--font-size-xl);
    font-weight: 600;
    color: var(--term-green);
}

.stat-label {
    font-size: var(--font-size-sm);
    color: var(--term-green-dim);
    margin-top: var(--spacing-xs);
}

/* Fuzzing results */
.fuzz-results {
    display: flex;
    flex-direction: column;
    gap: var(--spacing-sm);
}

.result-row {
    display: flex;
    justify-content: space-between;
    padding: var(--spacing-sm);
    border-bottom: 1px solid var(--term-green-dark);
}

/* Recommendations */
.recommendations {
    padding: var(--spacing-sm);
    background-color: rgba(0, 255, 65, 0.05);
    border-radius: var(--radius-sm);
}

.recommendations ul {
    margin-top: var(--spacing-sm);
    padding-left: var(--spacing-md);
}

.recommendations li {
    margin-bottom: var(--spacing-xs);
    color: var(--term-green-dim);
}

/* Header improvements */
.header-right {
    display: flex;
    align-items: center;
    gap: var(--spacing-md);
}

/* Privilege indicator */
.priv-indicator {
    display: inline-flex;
    align-items: center;
    gap: var(--spacing-xs);
    padding: 2px var(--spacing-sm);
    border-radius: var(--radius-sm);
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.5px;
    border: 1px solid var(--term-green-dark);
}

.priv-indicator.root {
    color: var(--term-green);
    border-color: var(--term-green);
    background-color: rgba(0, 255, 65, 0.08);
}

.priv-indicator.user {
    color: var(--term-amber);
    border-color: var(--term-amber);
    background-color: rgba(255, 176, 0, 0.08);
}

/* Privilege banner shown below tab bar when not privileged */
.priv-banner {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--spacing-md);
    padding: var(--spacing-sm) var(--spacing-md);
    background-color: rgba(255, 176, 0, 0.08);
    border-bottom: 1px solid var(--term-amber);
    color: var(--term-amber);
    font-size: var(--font-size-sm);
}

.priv-banner-text {
    flex: 1;
}

.priv-banner-text strong {
    color: var(--term-amber);
    font-weight: 600;
}

.priv-banner-features {
    color: var(--term-amber);
    opacity: 0.85;
}

.priv-banner-hint {
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--term-green-dim);
    padding: 2px 6px;
    border: 1px solid var(--term-green-dark);
    border-radius: var(--radius-sm);
    background-color: rgba(0, 0, 0, 0.3);
    white-space: nowrap;
}

.priv-banner-close {
    background: transparent;
    border: 1px solid var(--term-amber);
    color: var(--term-amber);
    padding: 2px var(--spacing-sm);
    border-radius: var(--radius-sm);
    cursor: pointer;
    font-size: 11px;
}

.priv-banner-close:hover {
    background-color: rgba(255, 176, 0, 0.15);
}

.progress-container {
    width: 200px;
}

/* VPN grid improvements */
.vpn-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: var(--spacing-sm);
}

.overhead {
    font-size: 10px;
    color: var(--term-amber);
    margin-left: var(--spacing-xs);
}

/* Terminal output */
.terminal-output {
    background-color: var(--term-black);
    border: 1px solid var(--term-green-dark);
    border-radius: var(--radius-sm);
    padding: var(--spacing-md);
    font-family: var(--font-mono);
    font-size: var(--font-size-sm);
    color: var(--term-green);
    white-space: pre-wrap;
    overflow-x: auto;
    max-height: 300px;
    overflow-y: auto;
}

/* Waterfall error state */
.waterfall-fill.error {
    background-color: var(--term-red);
}

/* Detached window styles */
.detached-window {
    height: 100vh;
    display: flex;
    flex-direction: column;
}

.detached-window .header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: var(--spacing-sm) var(--spacing-md);
    border-bottom: 1px solid var(--term-green-dark);
    background: linear-gradient(180deg, rgba(0, 255, 65, 0.1) 0%, transparent 100%);
}

.detached-window .content {
    flex: 1;
    overflow: auto;
    padding: var(--spacing-md);
}

/* Panel container */
.panel-container {
    position: relative;
    height: 100%;
}

/* Detached panel placeholder */
.panel-detached-message {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    height: 300px;
    gap: var(--spacing-md);
    color: var(--term-green-dim);
    border: 2px dashed var(--term-green-dark);
    border-radius: var(--radius-md);
    margin: var(--spacing-lg);
}

.panel-detached-message p {
    font-size: var(--font-size-lg);
}

/* Detached indicator in tab bar */
.detached-indicator {
    margin-left: auto;
    padding: var(--spacing-xs) var(--spacing-sm);
    color: var(--term-amber);
    font-size: 11px;
    border: 1px solid var(--term-amber);
    border-radius: var(--radius-sm);
    opacity: 0.8;
}

/* Detach/Reattach button */
.detach-btn {
    padding: var(--spacing-xs) var(--spacing-sm);
    border: 1px solid var(--term-green-dark);
    border-radius: var(--radius-sm);
    background: transparent;
    color: var(--term-green-dim);
    cursor: pointer;
    font-family: var(--font-mono);
    font-size: 11px;
    transition: all 0.2s ease;
    white-space: nowrap;
}

.detach-btn:hover {
    border-color: var(--term-green);
    color: var(--term-green);
    background-color: rgba(0, 255, 65, 0.1);
}

.detach-btn.reattach {
    border-color: var(--term-amber);
    color: var(--term-amber);
}

.detach-btn.reattach:hover {
    background-color: rgba(255, 176, 0, 0.1);
}

/* Logs Panel */
.logs-panel {
    height: 100%;
    display: flex;
    flex-direction: column;
    gap: var(--spacing-md);
}

.current-status {
    padding: var(--spacing-md);
    background-color: rgba(0, 255, 65, 0.05);
    border-radius: var(--radius-sm);
}

.status-indicator {
    width: 12px;
    height: 12px;
    border-radius: 50%;
    display: inline-block;
}

.status-indicator.running {
    background-color: var(--term-amber);
    animation: pulse 1s infinite;
}

@keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.5; }
}

.log-container {
    flex: 1;
    display: flex;
    flex-direction: column;
    min-height: 0;
}

.log-entries {
    flex: 1;
    overflow-y: auto;
    font-family: var(--font-mono);
    font-size: 12px;
    padding: var(--spacing-sm);
    background-color: rgba(0, 0, 0, 0.3);
    border-radius: var(--radius-sm);
}

.log-entry {
    display: flex;
    gap: var(--spacing-sm);
    padding: 2px 0;
    border-bottom: 1px solid rgba(0, 255, 65, 0.1);
}

.log-time {
    color: var(--term-green-dark);
    min-width: 70px;
}

.log-level {
    min-width: 30px;
    font-weight: bold;
}

.log-message {
    flex: 1;
}

.log-info .log-level { color: var(--term-green-dim); }
.log-running .log-level { color: var(--term-amber); }
.log-success .log-level { color: var(--term-green); }
.log-warning .log-level { color: var(--term-amber); }
.log-error .log-level { color: var(--term-red); }

.log-success .log-message { color: var(--term-green); }
.log-error .log-message { color: var(--term-red); }
.log-warning .log-message { color: var(--term-amber); }

/* Expandable log entries */
.log-entry-container {
    border-bottom: 1px solid rgba(0, 255, 65, 0.1);
}

.log-expand {
    min-width: 30px;
    color: var(--term-cyan);
    font-family: monospace;
}

.log-entry:hover {
    background-color: rgba(0, 255, 65, 0.05);
}

.log-details {
    margin-left: 30px;
    padding: var(--spacing-sm) var(--spacing-md);
    background-color: rgba(0, 0, 0, 0.3);
    border-left: 2px solid var(--term-green-dark);
    margin-bottom: var(--spacing-xs);
}

.log-detail-section {
    margin-bottom: var(--spacing-sm);
}

.log-detail-section:last-child {
    margin-bottom: 0;
}

.log-detail-label {
    display: block;
    color: var(--term-green-dim);
    font-size: 11px;
    margin-bottom: 4px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

.log-detail-code {
    display: block;
    font-family: 'SF Mono', 'Menlo', 'Monaco', monospace;
    font-size: 12px;
    color: var(--term-cyan);
    background-color: rgba(0, 0, 0, 0.4);
    padding: var(--spacing-xs) var(--spacing-sm);
    border-radius: var(--radius-sm);
    overflow-x: auto;
    white-space: pre-wrap;
    word-break: break-all;
}

.log-metrics-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
    gap: var(--spacing-xs);
}

.log-metric {
    display: flex;
    gap: var(--spacing-xs);
    font-size: 12px;
}

.log-metric-key {
    color: var(--term-green-dim);
}

.log-metric-value {
    color: var(--term-green);
}

.log-detail-output {
    font-family: 'SF Mono', 'Menlo', 'Monaco', monospace;
    font-size: 11px;
    color: var(--term-green-dim);
    background-color: rgba(0, 0, 0, 0.4);
    padding: var(--spacing-sm);
    border-radius: var(--radius-sm);
    overflow-x: auto;
    white-space: pre-wrap;
    max-height: 200px;
    overflow-y: auto;
}

.no-logs {
    padding: var(--spacing-xl);
    text-align: center;
    color: var(--term-green-dim);
}

/* History Panel */
.history-panel {
    height: 100%;
}

.history-list {
    display: flex;
    flex-direction: column;
    gap: var(--spacing-xs);
}

.history-item {
    padding: var(--spacing-sm);
    border: 1px solid var(--term-green-dark);
    border-radius: var(--radius-sm);
    cursor: pointer;
    transition: all 0.2s ease;
}

.history-item:hover {
    border-color: var(--term-green);
    background-color: rgba(0, 255, 65, 0.05);
}

.history-item.selected {
    border-color: var(--term-green);
    background-color: rgba(0, 255, 65, 0.1);
}

.history-item-header {
    display: flex;
    justify-content: space-between;
    margin-bottom: var(--spacing-xs);
}

.history-target {
    font-weight: 600;
    color: var(--term-green);
}

.history-category {
    font-size: 11px;
    color: var(--term-cyan);
    padding: 2px 6px;
    background-color: rgba(0, 255, 200, 0.1);
    border-radius: var(--radius-sm);
}

.history-item-meta {
    display: flex;
    justify-content: space-between;
    font-size: 11px;
    color: var(--term-green-dim);
    margin-bottom: var(--spacing-xs);
}

.history-item-stats {
    font-size: 12px;
}

.history-detail {
    padding: var(--spacing-sm);
}

.no-selection, .no-history {
    display: flex;
    align-items: center;
    justify-content: center;
    height: 200px;
    color: var(--term-green-dim);
}

/* Stop button styling */
.btn.danger {
    border-color: var(--term-red);
    color: var(--term-red);
}

.btn.danger:hover {
    background-color: var(--term-red);
    color: var(--term-black);
    box-shadow: 0 0 10px var(--term-red);
}

/* Fuzzing status display */
.fuzz-status {
    display: flex;
    flex-direction: column;
    gap: var(--spacing-xs);
    padding: var(--spacing-sm);
    background-color: rgba(0, 255, 65, 0.03);
    border-radius: var(--radius-sm);
    border: 1px solid var(--term-green-dark);
}

.fuzz-status .status-row {
    display: flex;
    gap: var(--spacing-sm);
    font-size: var(--font-size-sm);
}

.fuzz-status .status-label {
    color: var(--term-green-dim);
    min-width: 60px;
}

.fuzz-status .status-value {
    color: var(--term-green);
    word-break: break-all;
}

/* Fuzzing controls */
.fuzz-controls {
    display: flex;
    flex-wrap: wrap;
    gap: var(--spacing-sm);
    align-items: center;
}

.fuzz-controls .progress-bar {
    min-width: 100px;
}

/* Target Input with Dropdown */
.target-input-container {
    position: relative;
    flex: 1;
}

.target-input-row {
    display: flex;
    gap: 0;
}

.target-text-input {
    flex: 1;
    border-radius: var(--radius-sm) 0 0 var(--radius-sm) !important;
    border-right: none !important;
}

.dropdown-toggle {
    padding: var(--spacing-sm) var(--spacing-md);
    border: 1px solid var(--term-green-dark);
    border-radius: 0 var(--radius-sm) var(--radius-sm) 0;
    background: transparent;
    color: var(--term-green);
    cursor: pointer;
    font-family: var(--font-mono);
    font-size: var(--font-size-sm);
    transition: all 0.2s ease;
}

.dropdown-toggle:hover {
    background-color: rgba(0, 255, 65, 0.1);
    border-color: var(--term-green);
}

.target-dropdown {
    position: absolute;
    top: 100%;
    left: 0;
    right: 0;
    margin-top: 4px;
    background-color: var(--term-black);
    border: 1px solid var(--term-green);
    border-radius: var(--radius-sm);
    box-shadow: 0 4px 20px rgba(0, 255, 65, 0.2);
    z-index: 1000;
    max-height: 400px;
    display: flex;
    flex-direction: column;
}

.dropdown-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: var(--spacing-sm) var(--spacing-md);
    border-bottom: 1px solid var(--term-green-dark);
    color: var(--term-green);
    font-weight: 600;
}

.dropdown-close {
    background: transparent;
    border: none;
    color: var(--term-green-dim);
    cursor: pointer;
    font-size: 18px;
    padding: 0 4px;
}

.dropdown-close:hover {
    color: var(--term-green);
}

.dropdown-content {
    overflow-y: auto;
    flex: 1;
}

.dropdown-category {
    border-bottom: 1px solid var(--term-green-dark);
}

.dropdown-category:last-child {
    border-bottom: none;
}

.category-header {
    padding: var(--spacing-sm) var(--spacing-md);
    color: var(--term-cyan);
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    background-color: rgba(0, 255, 200, 0.05);
    position: sticky;
    top: 0;
}

.dropdown-item {
    display: grid;
    grid-template-columns: 1fr auto auto;
    gap: var(--spacing-sm);
    padding: var(--spacing-sm) var(--spacing-md);
    cursor: pointer;
    transition: background-color 0.15s ease;
}

.dropdown-item:hover {
    background-color: rgba(0, 255, 65, 0.1);
}

.item-host {
    color: var(--term-green);
    font-weight: 500;
}

.item-desc {
    color: var(--term-green-dim);
    font-size: 12px;
}

.item-port {
    color: var(--term-amber);
    font-size: 11px;
    min-width: 50px;
    text-align: right;
}

/* Dimmed items (incompatible with selected test) */
.dropdown-item.dimmed {
    opacity: 0.4;
}

.dropdown-item.dimmed:hover {
    opacity: 0.6;
    background-color: rgba(255, 176, 0, 0.05);
}

.dropdown-item.dimmed .item-host {
    color: var(--term-green-dim);
}

.category-count {
    color: var(--term-green);
    font-weight: normal;
}
"#
}
