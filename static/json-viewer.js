/**
 * JSON Viewer with Monaco Editor
 * Provides search, download, copy, expand/collapse, and syntax highlighting
 */

console.log('JSON Viewer script loading...');

let monacoEditor = null;
let currentSearchIndex = 0;
let searchMatches = [];

function openJsonViewer() {
    console.log('openJsonViewer called');

    const modal = document.getElementById('jsonViewerModal');
    if (!modal) {
        console.error('Modal element not found');
        return;
    }

    modal.classList.add('active');
    console.log('Modal opened');

    if (typeof window.fetchResults === 'function') {
        console.log('Fetching results...');
        window.fetchResults()
            .then(data => {
                console.log('Data fetched successfully');
                const jsonString = JSON.stringify(data, null, 2);
                initMonacoEditor(jsonString);
            })
            .catch(err => {
                console.error('Failed to load JSON:', err);
                closeJsonViewer();
                alert('Failed to load JSON results: ' + err.message);
            });
    } else {
        console.error('fetchResults function not available');
        closeJsonViewer();
        alert('Error: Results function not available');
    }
}

function closeJsonViewer() {
    const modal = document.getElementById('jsonViewerModal');
    if (!modal) return;

    modal.classList.remove('active');
    if (monacoEditor) {
        monacoEditor.dispose();
        monacoEditor = null;
    }
    clearJsonSearch();
}

function initMonacoEditor(jsonContent) {
    console.log('initMonacoEditor called');

    const container = document.getElementById('jsonEditorContainer');
    if (!container) {
        console.error('Container not found');
        return;
    }

    container.innerHTML = '';

    loadMonacoLoader()
        .then(() => {
            createMonacoEditor(jsonContent, container);
        })
        .catch((err) => {
            console.warn('Monaco loader unavailable, falling back to textarea', err);
            showTextareaFallback(jsonContent, container);
        });
}

function loadMonacoLoader() {
    // If require is already available, resolve immediately
    if (typeof window.require === 'function' && window.require.config) {
        return Promise.resolve();
    }

    const existing = document.getElementById('monaco-loader-script');
    if (existing) {
        return new Promise((resolve, reject) => {
            existing.addEventListener('load', () => resolve(), { once: true });
            existing.addEventListener('error', () => reject(new Error('Failed to load Monaco loader')), { once: true });
        });
    }

    return new Promise((resolve, reject) => {
        const script = document.createElement('script');
        script.id = 'monaco-loader-script';
        script.src = 'https://cdnjs.cloudflare.com/ajax/libs/monaco-editor/0.45.0/min/vs/loader.min.js';
        script.onload = () => resolve();
        script.onerror = () => reject(new Error('Failed to load Monaco loader'));
        document.head.appendChild(script);
    });
}

function createMonacoEditor(jsonContent, container) {
    try {
        console.log('Creating Monaco editor...');

        if (typeof window.require !== 'function') {
            throw new Error('Monaco require not available');
        }

        window.require.config({
            paths: {
                'vs': 'https://cdnjs.cloudflare.com/ajax/libs/monaco-editor/0.45.0/min/vs'
            }
        });

        window.require(['vs/editor/editor.main'], function () {
            try {
                const isDarkMode = document.body.classList.contains('dark-mode');
                const theme = isDarkMode ? 'vs-dark' : 'vs';

                monacoEditor = monaco.editor.create(container, {
                    value: jsonContent,
                    language: 'json',
                    theme: theme,
                    readOnly: true,
                    automaticLayout: true,
                    minimap: { enabled: true },
                    scrollBeyondLastLine: false,
                    wordWrap: 'on',
                    lineNumbers: 'on',
                    folding: true,
                    foldingStrategy: 'indentation',
                    fontSize: 13
                });

                console.log('Monaco editor created successfully');
            } catch (error) {
                console.error('Error creating Monaco editor:', error);
                showTextareaFallback(jsonContent, container);
            }
        });
    } catch (error) {
        console.error('Error in createMonacoEditor:', error);
        showTextareaFallback(jsonContent, container);
    }
}

function showTextareaFallback(jsonContent, container) {
    console.log('Using textarea fallback');
    if (!container) {
        container = document.getElementById('jsonEditorContainer');
        if (!container) return;
    }

    container.innerHTML = '';
    const textarea = document.createElement('textarea');
    textarea.id = 'jsonTextarea';
    textarea.style.cssText = `
        width: 100%;
        height: 100%;
        border: none;
        padding: 1rem;
        font-family: Monaco, Menlo, Consolas, monospace;
        font-size: 13px;
        background: var(--surface-color);
        color: var(--text-color);
        resize: none;
        box-sizing: border-box;
    `;
    textarea.value = jsonContent;
    textarea.readOnly = true;
    container.appendChild(textarea);
}

function expandAllJson() {
    if (!monacoEditor) {
        console.log('Expand/collapse not available in textarea mode');
        return;
    }
    monacoEditor.trigger('keyboard', 'editor.unfoldAll');
}

function collapseAllJson() {
    if (!monacoEditor) {
        console.log('Expand/collapse not available in textarea mode');
        return;
    }
    monacoEditor.trigger('keyboard', 'editor.foldAll');
}

function copyJsonToClipboard() {
    const container = document.getElementById('jsonEditorContainer');
    if (!container) return;

    let content;
    if (monacoEditor) {
        content = monacoEditor.getValue();
    } else {
        const textarea = container.querySelector('textarea');
        if (!textarea) return;
        content = textarea.value;
    }

    navigator.clipboard.writeText(content).then(() => {
        notifyCopy('JSON copied to clipboard');
    }).catch(err => {
        console.error('Failed to copy:', err);
        alert('Failed to copy to clipboard');
    });
}

function downloadJson() {
    const container = document.getElementById('jsonEditorContainer');
    if (!container) return;

    let content;
    if (monacoEditor) {
        content = monacoEditor.getValue();
    } else {
        const textarea = container.querySelector('textarea');
        if (!textarea) return;
        content = textarea.value;
    }

    const blob = new Blob([content], { type: 'application/json' });
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'analysis-results.json';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.URL.revokeObjectURL(url);
}

function findInJson() {
    const searchInput = document.getElementById('jsonSearchInput');
    if (!searchInput) return;

    const searchTerm = searchInput.value.trim();
    if (!searchTerm) {
        clearJsonSearch();
        return;
    }

    if (!monacoEditor) {
        console.log('Search not available in textarea mode');
        return;
    }

    clearJsonSearch();

    const content = monacoEditor.getValue();
    let index = content.indexOf(searchTerm);

    while (index !== -1) {
        searchMatches.push(index);
        index = content.indexOf(searchTerm, index + 1);
    }

    if (searchMatches.length > 0) {
        currentSearchIndex = 0;
        highlightCurrentMatch();
    }

    updateSearchStatus();
}

function findPrevInJson() {
    if (searchMatches.length === 0) return;
    currentSearchIndex = (currentSearchIndex - 1 + searchMatches.length) % searchMatches.length;
    highlightCurrentMatch();
}

function highlightCurrentMatch() {
    if (!monacoEditor || currentSearchIndex < 0 || currentSearchIndex >= searchMatches.length) return;

    const searchInput = document.getElementById('jsonSearchInput');
    if (!searchInput) return;

    const searchTerm = searchInput.value.trim();
    const matchIndex = searchMatches[currentSearchIndex];
    const content = monacoEditor.getValue();

    let line = 1;
    let column = 1;
    for (let i = 0; i < matchIndex; i++) {
        if (content[i] === '\n') {
            line++;
            column = 1;
        } else {
            column++;
        }
    }

    monacoEditor.setSelection(
        new monaco.Range(line, column, line, column + searchTerm.length)
    );
    monacoEditor.revealLineInCenter(line);
}

function clearJsonSearch() {
    searchMatches = [];
    currentSearchIndex = 0;
    if (monacoEditor) {
        monacoEditor.setSelection(new monaco.Range(1, 1, 1, 1));
    }
    updateSearchStatus();
}

function updateSearchStatus() {
    const status = document.getElementById('jsonSearchStatus');
    if (!status) return;

    if (searchMatches.length === 0) {
        status.textContent = '';
    } else {
        status.textContent = `Match ${currentSearchIndex + 1} of ${searchMatches.length}`;
    }
}

function showNotification(message) {
    const notification = document.createElement('div');
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: #4CAF50;
        color: white;
        padding: 12px 20px;
        border-radius: 4px;
        font-size: 14px;
        z-index: 10000;
        animation: slideIn 0.3s ease-out;
    `;
    notification.textContent = message;
    document.body.appendChild(notification);

    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease-out';
        setTimeout(() => notification.remove(), 300);
    }, 2000);
}

function notifyCopy(message) {
    if (typeof window.showToast === 'function') {
        window.showToast(message);
    } else {
        showNotification(message);
    }
}

function initializeEventListeners() {
    console.log('Initializing event listeners');

    const searchInput = document.getElementById('jsonSearchInput');
    const searchNextBtn = document.getElementById('jsonSearchNext');
    const searchPrevBtn = document.getElementById('jsonSearchPrev');
    const expandBtn = document.getElementById('jsonExpandBtn');
    const collapseBtn = document.getElementById('jsonCollapseBtn');
    const copyBtn = document.getElementById('jsonCopyBtn');
    const downloadBtn = document.getElementById('jsonDownloadBtn');
    const closeBtn = document.getElementById('jsonCloseBtn');

    if (searchInput) {
        searchInput.addEventListener('keyup', findInJson);
        searchInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                findInJson();
            }
        });
    }

    if (searchNextBtn) {
        searchNextBtn.addEventListener('click', findInJson);
    }

    if (searchPrevBtn) {
        searchPrevBtn.addEventListener('click', findPrevInJson);
    }

    if (expandBtn) {
        expandBtn.addEventListener('click', expandAllJson);
    }

    if (collapseBtn) {
        collapseBtn.addEventListener('click', collapseAllJson);
    }

    if (copyBtn) {
        copyBtn.addEventListener('click', copyJsonToClipboard);
    }

    if (downloadBtn) {
        downloadBtn.addEventListener('click', downloadJson);
    }

    if (closeBtn) {
        closeBtn.addEventListener('click', closeJsonViewer);
    }
}

// Initialize event listeners when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeEventListeners);
} else {
    initializeEventListeners();
}

console.log('JSON Viewer script initialized successfully');
