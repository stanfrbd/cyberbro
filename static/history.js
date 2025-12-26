/**
 * History Page Functionality
 * Handles search/filter functionality for analysis history
 */

function filterTable() {
    const searchInput = document.getElementById("searchInput").value.toLowerCase();
    const table = document.getElementById("historyTable");
    const tr = table.getElementsByTagName("tr");

    for (let i = 1; i < tr.length; i++) {
        let td = tr[i].getElementsByTagName("td");
        let showRow = true;

        const observablesInAnalysis = tr[i].querySelector("#observables-in-analysis");
        if (observablesInAnalysis) {
            observablesInAnalysis.innerText = observablesInAnalysis.title;
        }

        const enginesInAnalysis = tr[i].querySelector("#engines-in-analysis");
        if (enginesInAnalysis) {
            enginesInAnalysis.innerText = enginesInAnalysis.title;
        }

        if (searchInput) {
            showRow = Array.from(td).some(cell =>
                cell.innerText.toLowerCase().includes(searchInput) ||
                (cell.querySelector('p') && cell.querySelector('p').title.toLowerCase().includes(searchInput))
            );
        }

        // Highlight matching text in search results
        if (searchInput) {
            Array.from(td).forEach(cell => {
                if (cell.querySelector('p')) {
                    cell.querySelector('p').innerHTML = cell.querySelector('p').title.replace(
                        new RegExp(searchInput, 'gi'),
                        match => `<mark class="search-highlight">${match}</mark>`
                    );
                }
            });
        }

        tr[i].style.display = showRow ? "" : "none";
    }
}
