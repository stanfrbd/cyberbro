/**
 * History Table Client-side Filter
 * Only filters visible rows on current page for better performance
 */

/**
 * Client-side filter for current page
 */
function filterTable() {
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

