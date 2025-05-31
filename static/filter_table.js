function filterTable() {
    const searchInput = document.getElementById("searchInput").value.toLowerCase();
    const countryFilter = document.getElementById("countryFilter").value.toLowerCase();
    const riskFilter = document.getElementById("riskFilter").value.toLowerCase();
    const detectionFilter = document.getElementById("detectionFilter").value.toLowerCase();
    const typeFilter = document.getElementById("typeFilter").value.toLowerCase();
    const proxyVpnFilter = document.getElementById("proxyVpnFilter").value.toLowerCase();
    const table = document.getElementById("resultsTable");
    const tr = table.getElementsByTagName("tr");

    for (let i = 1; i < tr.length; i++) {
        let td = tr[i].getElementsByTagName("td");
        let showRow = true;

        if (searchInput) {
            showRow = Array.from(td).some(cell => cell.innerText.toLowerCase().includes(searchInput));
        }

        if (showRow && countryFilter !== "all") {
            const countrySpan = tr[i].querySelector(".country");
            const country = countrySpan ? countrySpan.className.split("-")[1] : "";
            showRow = country === countryFilter;
        }

        if (showRow && riskFilter !== "all") {
            const riskClass = tr[i].classList.contains("high-risk") ? "high" : "low";
            showRow = riskClass === riskFilter;
        }

        if (showRow && detectionFilter !== "all") {
            const detectionClass = tr[i].classList.contains("high-detection") ? "high" : tr[i].classList.contains("clean-detection") ? "clean" : "low";
            showRow = detectionClass === detectionFilter;
        }

        if (showRow && typeFilter !== "all") {
            showRow = td[1].innerText.toLowerCase() === typeFilter;
        }

        // Spur or IP Quality Score
        if (showRow && proxyVpnFilter !== "all") {
            let anonymousResult = "";
            anonymousResult = tr[i].innerText.toLowerCase();
            showRow = anonymousResult.includes(proxyVpnFilter);
        }

        tr[i].style.display = showRow ? "" : "none";
    }
}

function clearFilters() {
    document.getElementById("searchInput").value = "";
    document.getElementById("countryFilter").value = "all";
    document.getElementById("riskFilter").value = "all";
    document.getElementById("detectionFilter").value = "all";
    document.getElementById("typeFilter").value = "all";
    document.getElementById("proxyVpnFilter").value = "all";
    filterTable();
}
