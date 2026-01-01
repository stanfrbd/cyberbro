/**
 * History Table Search Functionality
 * Supports both client-side filtering (current page) and server-side search (entire database)
 */

let searchTimeout = null;

/**
 * Client-side filter for current page
 */
function filterTableClientSide() {
    const searchInput = document.getElementById("searchInput");
    if (!searchInput) return;

    const searchValue = searchInput.value.toLowerCase();
    const table = document.getElementById("historyTable");
    if (!table) return;

    const tr = table.getElementsByTagName("tr");

    for (let i = 1; i < tr.length; i++) {
        let td = tr[i].getElementsByTagName("td");
        let showRow = true;

        // Always expand observables to full content
        const observablesInAnalysis = tr[i].querySelector(".observables-in-analysis");
        if (observablesInAnalysis && observablesInAnalysis.title) {
            observablesInAnalysis.innerText = observablesInAnalysis.title;
        }

        // Always expand engines to full content
        const enginesInAnalysis = tr[i].querySelector(".engines-in-analysis");
        if (enginesInAnalysis && enginesInAnalysis.title) {
            enginesInAnalysis.innerText = enginesInAnalysis.title;
        }

        // Filter rows if search input exists
        if (searchValue) {
            showRow = Array.from(td).some(cell =>
                cell.innerText.toLowerCase().includes(searchValue) ||
                (cell.querySelector('p') && cell.querySelector('p').title && cell.querySelector('p').title.toLowerCase().includes(searchValue))
            );
        }

        // Highlight matching text if search input exists
        if (searchValue) {
            Array.from(td).forEach(cell => {
                const p = cell.querySelector('p');
                if (p && p.title) {
                    p.innerHTML = p.title.replace(new RegExp(searchValue, 'gi'), match => `<span style="background-color: yellow;">${match}</span>`);
                }
            });
        }

        tr[i].style.display = showRow ? "" : "none";
    }
}

/**
 * Server-side search (searches entire database)
 */
function searchDatabase() {
    const searchInput = document.getElementById("searchInput");
    const searchTypeSelect = document.getElementById("searchTypeSelect");
    if (!searchInput) return;

    const searchValue = searchInput.value.trim();
    const searchType = searchTypeSelect ? searchTypeSelect.value : 'observable';
    const url = new URL(window.location);

    if (searchValue) {
        url.searchParams.set('search', searchValue);
        url.searchParams.set('search_type', searchType);
        url.searchParams.set('page', 1); // Reset to first page
    } else {
        url.searchParams.delete('search');
        url.searchParams.delete('search_type');
    }

    // Show loading feedback on input
    searchInput.disabled = true;
    searchInput.style.opacity = '0.6';

    // Show loading feedback on button
    const searchBtn = document.getElementById('searchAllBtn');
    if (searchBtn) {
        searchBtn.disabled = true;
        searchBtn.textContent = 'Searching...';
        searchBtn.style.opacity = '0.6';
    }

    console.log('Navigating to:', url.toString());
    window.location.href = url.toString();
}

/**
 * Main filter function - called by onkeyup
 * Uses client-side filtering by default
 */
function filterTable() {
    // Clear any pending timeout
    if (searchTimeout) {
        clearTimeout(searchTimeout);
    }

    // Client-side filtering (immediate)
    filterTableClientSide();
}

/**
 * Handle search input key events
 */
function handleSearchKeyDown(event) {
    // Enter key triggers server-side search
    if (event.key === 'Enter') {
        event.preventDefault();
        event.stopPropagation();
        console.log('Enter pressed - triggering server search');
        searchDatabase();
        return false;
    }
}

/**
 * Clear search and reload
 */
function clearSearch() {
    const url = new URL(window.location);
    url.searchParams.delete('search');
    url.searchParams.delete('search_type');
    url.searchParams.set('page', 1);
    window.location.href = url.toString();
}

// Initialize search functionality
document.addEventListener('DOMContentLoaded', function() {
    const searchInput = document.getElementById('searchInput');
    if (searchInput) {
        // Use keydown instead of keypress (more reliable)
        searchInput.addEventListener('keydown', handleSearchKeyDown);

        // Log for debugging
        console.log('Search input initialized');
    } else {
        console.warn('Search input not found');
    }
});

