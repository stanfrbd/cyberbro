/**
 * Single Observable Copy Functionality
 * Handles copying the observable in single observable card view
 */

// Get observable value from data attribute or global variable
let observableValue = '';

function initSingleObservableCopy(observable) {
    observableValue = observable;
}

async function copySingleObservable() {
    try {
        await navigator.clipboard.writeText(observableValue);
        showToast('Observable copied to clipboard!');
    } catch (err) {
        // Fallback for older browsers
        const textArea = document.createElement('textarea');
        textArea.value = observableValue;
        textArea.style.position = 'fixed';
        textArea.style.left = '-999999px';
        document.body.appendChild(textArea);
        textArea.select();

        try {
            document.execCommand('copy');
            showToast('Observable copied to clipboard!');
        } catch (err) {
            console.error('Failed to copy:', err);
            showToast('Failed to copy', 'error');
        }

        document.body.removeChild(textArea);
    }
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
