/**
 * Table Fullscreen Functionality
 * Handles table fullscreen toggle and ESC key handling
 */

function toggleTableFullscreen() {
    const container = document.getElementById('tableContainer');
    const btn = document.getElementById('fullscreenBtn');
    const hint = document.getElementById('escapeHint');

    if (container.classList.contains('fullscreen')) {
        // Exit fullscreen
        container.classList.remove('fullscreen');
        btn.innerHTML = '<span>⛶</span><span>Expand Table</span>';
        hint.style.display = 'none';
        document.body.style.overflow = '';
    } else {
        // Enter fullscreen
        container.classList.add('fullscreen');
        btn.innerHTML = '<span>⛶</span><span>Exit Fullscreen</span>';
        hint.style.display = 'inline-block';
        document.body.style.overflow = 'hidden';
    }
}

// ESC key to exit fullscreen
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
        const container = document.getElementById('tableContainer');
        if (container && container.classList.contains('fullscreen')) {
            toggleTableFullscreen();
        }
    }
});
