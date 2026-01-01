/**
 * Pagination Component
 * Handles URL-based pagination navigation
 */

/**
 * Generate pagination range with ellipsis
 * @param {number} currentPage - Current page number
 * @param {number} totalPages - Total number of pages
 * @param {number} delta - Number of pages to show around current page
 * @returns {Array} Array of page numbers and ellipsis markers
 */
function getPaginationRange(currentPage, totalPages, delta = 2) {
    const range = [];
    const rangeWithDots = [];
    let l;

    // Always show first page
    range.push(1);

    // Add pages around current page
    for (let i = currentPage - delta; i <= currentPage + delta; i++) {
        if (i > 1 && i < totalPages) {
            range.push(i);
        }
    }

    // Always show last page if more than 1 page
    if (totalPages > 1) {
        range.push(totalPages);
    }

    // Add ellipsis where needed
    for (let i of range) {
        if (l) {
            if (i - l === 2) {
                rangeWithDots.push(l + 1);
            } else if (i - l !== 1) {
                rangeWithDots.push('...');
            }
        }
        rangeWithDots.push(i);
        l = i;
    }

    return rangeWithDots;
}

/**
 * Navigate to a specific page
 * @param {number} page - Page number to navigate to
 */
function goToPage(page) {
    const url = new URL(window.location);
    url.searchParams.set('page', page);
    window.location.href = url.toString();
}

/**
 * Change items per page
 * @param {number} perPage - Number of items per page
 */
function changePerPage(perPage) {
    const url = new URL(window.location);
    url.searchParams.set('per_page', perPage);
    url.searchParams.set('page', 1); // Reset to first page
    window.location.href = url.toString();
}

/**
 * Change time range filter
 * @param {string} timeRange - Time range to filter by ('7d', '30d', 'all')
 */
function changeTimeRange(timeRange) {
    const url = new URL(window.location);
    url.searchParams.set('time_range', timeRange);
    url.searchParams.set('page', 1); // Reset to first page
    window.location.href = url.toString();
}

/**
 * Initialize pagination controls
 */
function initPagination() {
    // Get pagination data from data attributes
    const container = document.getElementById('paginationContainer');
    if (!container) return;

    const currentPage = parseInt(container.dataset.currentPage);
    const totalPages = parseInt(container.dataset.totalPages);
    const perPage = parseInt(container.dataset.perPage);
    const totalCount = parseInt(container.dataset.totalCount);

    // Update page info
    const pageInfo = document.getElementById('pageInfo');
    if (pageInfo) {
        const start = (currentPage - 1) * perPage + 1;
        const end = Math.min(currentPage * perPage, totalCount);
        pageInfo.textContent = `Showing ${start}-${end} of ${totalCount}`;
    }

    // Generate pagination buttons
    const paginationButtons = document.getElementById('paginationButtons');
    if (paginationButtons && totalPages > 1) {
        paginationButtons.innerHTML = '';

        // Previous button
        const prevBtn = createPaginationButton(
            '‹',
            currentPage - 1,
            currentPage === 1,
            'Previous page'
        );
        paginationButtons.appendChild(prevBtn);

        // Page number buttons
        const pageRange = getPaginationRange(currentPage, totalPages);
        pageRange.forEach(page => {
            if (page === '...') {
                const ellipsis = document.createElement('span');
                ellipsis.className = 'pagination-ellipsis';
                ellipsis.textContent = '...';
                paginationButtons.appendChild(ellipsis);
            } else {
                const btn = createPaginationButton(
                    page,
                    page,
                    false,
                    `Go to page ${page}`,
                    page === currentPage
                );
                paginationButtons.appendChild(btn);
            }
        });

        // Next button
        const nextBtn = createPaginationButton(
            '›',
            currentPage + 1,
            currentPage === totalPages,
            'Next page'
        );
        paginationButtons.appendChild(nextBtn);
    }

    // Set up per-page selector
    const perPageSelect = document.getElementById('perPageSelect');
    if (perPageSelect) {
        perPageSelect.value = perPage;
        perPageSelect.addEventListener('change', (e) => {
            changePerPage(parseInt(e.target.value));
        });
    }

    // Set up time range selector
    const timeRangeSelect = document.getElementById('timeRangeSelect');
    if (timeRangeSelect) {
        timeRangeSelect.addEventListener('change', (e) => {
            changeTimeRange(e.target.value);
        });
    }

    // Keyboard navigation
    document.addEventListener('keydown', (e) => {
        // Don't interfere if user is typing in an input
        if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') {
            return;
        }

        // Left arrow - previous page
        if (e.key === 'ArrowLeft' && currentPage > 1) {
            e.preventDefault();
            goToPage(currentPage - 1);
        }

        // Right arrow - next page
        if (e.key === 'ArrowRight' && currentPage < totalPages) {
            e.preventDefault();
            goToPage(currentPage + 1);
        }
    });
}

/**
 * Create a pagination button element
 * @param {string|number} text - Button text
 * @param {number} page - Page number to navigate to
 * @param {boolean} disabled - Whether button is disabled
 * @param {string} title - Button title/tooltip
 * @param {boolean} active - Whether this is the current page
 * @returns {HTMLElement} Button element
 */
function createPaginationButton(text, page, disabled = false, title = '', active = false) {
    const btn = document.createElement('button');
    btn.className = 'pagination-btn';

    if (disabled) {
        btn.classList.add('disabled');
        btn.disabled = true;
    }

    if (active) {
        btn.classList.add('active');
    }

    btn.textContent = text;
    btn.title = title;

    if (!disabled && !active) {
        btn.onclick = () => goToPage(page);
    }

    return btn;
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', initPagination);
