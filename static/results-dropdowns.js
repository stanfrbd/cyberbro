/**
 * Dropdown Menu Functionality for Results Page
 * Handles export and copy dropdown menus
 */

function toggleDropdown(id) {
    const dropdown = document.getElementById(id);
    const allDropdowns = document.querySelectorAll('.dropdown-menu');

    // Close all other dropdowns
    allDropdowns.forEach(d => {
        if (d.id !== id) {
            d.style.display = 'none';
        }
    });

    // Toggle this dropdown
    dropdown.style.display = dropdown.style.display === 'none' ? 'block' : 'none';
}

function closeAllDropdowns() {
    document.querySelectorAll('.dropdown-menu').forEach(d => {
        d.style.display = 'none';
    });
}

// Close dropdowns when clicking outside
document.addEventListener('click', function(event) {
    const isDropdownButton = event.target.closest('button[onclick*="toggleDropdown"]');
    const isDropdownMenu = event.target.closest('.dropdown-menu');

    if (!isDropdownButton && !isDropdownMenu) {
        closeAllDropdowns();
    }
});

/**
 * Fetch results from API
 * This function is set up by the template to fetch the current analysis results
 */
let fetchResults = null;

// Initialize fetchResults function when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    // This will be set by inline script in the template
    // fetchResults is intentionally left as a global that gets assigned from template context
});
