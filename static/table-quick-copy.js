/**
 * Quick Copy Functionality
 * Adds copy-to-clipboard buttons for observables
 */

function initQuickCopy() {
    const table = document.getElementById('resultsTable');
    if (!table) return;

    // Add copy buttons to observable cells ONLY (not expanded rows, not cells with nested tables)
    const observableCells = table.querySelectorAll('tbody tr:not(.expanded-row) td:nth-child(2)');

    observableCells.forEach(cell => {
        // Skip if already has copy button
        if (cell.querySelector('.copy-btn')) return;

        // Skip if cell contains a nested table (like Google DNS)
        if (cell.querySelector('table')) return;

        const observable = cell.textContent.trim();
        if (!observable || observable === 'N/A') return;

        // Create copy button container
        const container = document.createElement('span');
        container.style.display = 'inline-flex';
        container.style.alignItems = 'center';
        container.style.gap = '0.5rem';

        // Store original content
        const originalContent = cell.textContent;

        // Create copy button
        const copyBtn = document.createElement('button');
        copyBtn.className = 'copy-btn';
        copyBtn.innerHTML = '📋';
        copyBtn.title = 'Copy to clipboard';
        copyBtn.onclick = (e) => {
            e.stopPropagation();
            copyToClipboard(originalContent.trim(), copyBtn);
        };

        // Build: [original text] [copy button]
        container.innerHTML = cell.innerHTML;
        container.appendChild(copyBtn);

        cell.innerHTML = '';
        cell.appendChild(container);
    });
}

async function copyToClipboard(text, button) {
    try {
        await navigator.clipboard.writeText(text);
        showCopyFeedback(button, true);
    } catch (err) {
        // Fallback for older browsers
        const textArea = document.createElement('textarea');
        textArea.value = text;
        textArea.style.position = 'fixed';
        textArea.style.left = '-999999px';
        document.body.appendChild(textArea);
        textArea.select();

        try {
            document.execCommand('copy');
            showCopyFeedback(button, true);
        } catch (err) {
            console.error('Failed to copy:', err);
            showCopyFeedback(button, false);
        }

        document.body.removeChild(textArea);
    }
}

function showCopyFeedback(button, success) {
    const originalHTML = button.innerHTML;

    if (success) {
        button.innerHTML = '✅';
        button.style.backgroundColor = 'var(--success-color)';

        // Show toast notification
        showToast('Copied to clipboard!');
    } else {
        button.innerHTML = '❌';
        button.style.backgroundColor = 'var(--danger-color)';
        showToast('Failed to copy', 'error');
    }

    setTimeout(() => {
        button.innerHTML = originalHTML;
        button.style.backgroundColor = '';
    }, 1500);
}

function showToast(message, type = 'success') {
    // Remove existing toast
    const existingToast = document.querySelector('.copy-toast');
    if (existingToast) {
        existingToast.remove();
    }

    // Create toast
    const toast = document.createElement('div');
    toast.className = `copy-toast copy-toast-${type}`;
    toast.textContent = message;

    document.body.appendChild(toast);

    // Trigger animation
    setTimeout(() => toast.classList.add('show'), 10);

    // Remove after delay
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 300);
    }, 2000);
}

// Initialize quick copy when DOM is ready
document.addEventListener('DOMContentLoaded', initQuickCopy);

// Re-initialize after table filtering/updates
window.addEventListener('tableUpdated', initQuickCopy);
