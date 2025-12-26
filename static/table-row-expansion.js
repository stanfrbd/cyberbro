/**
 * Table Row Expansion Functionality
 * Handles expandable row details in vertical view
 */

function toggleRowExpansion(toggleCell) {
    const row = toggleCell.parentElement;
    const icon = toggleCell.querySelector('.toggle-icon');
    const nextRow = row.nextElementSibling;

    // Check if already expanded
    if (nextRow && nextRow.classList.contains('expanded-row')) {
        // Collapse
        nextRow.remove();
        icon.textContent = '›';
        icon.style.transform = 'rotate(0deg)';
        row.classList.remove('row-expanded');
    } else {
        // Expand - get only direct children cells, not nested table cells
        const cells = Array.from(row.children).filter(cell =>
            cell.tagName === 'TD' && !cell.classList.contains('row-toggle')
        );
        const headers = document.querySelectorAll('#resultsTable thead th:not(:first-child)');

        // Debug logging
        console.log('Number of cells:', cells.length);
        console.log('Number of headers:', headers.length);
        if (cells.length !== headers.length) {
            console.warn('Mismatch between cells and headers!');
        }

        // Create expanded row
        const expandedRow = document.createElement('tr');
        expandedRow.classList.add('expanded-row');

        // Copy row class (high-risk, warning, etc) to expanded row
        if (row.classList.contains('high-risk')) expandedRow.classList.add('high-risk');
        if (row.classList.contains('warning-row')) expandedRow.classList.add('warning-row');
        if (row.classList.contains('clean-detection')) expandedRow.classList.add('clean-detection');
        if (row.classList.contains('high-detection')) expandedRow.classList.add('high-detection');

        const expandedCell = document.createElement('td');
        expandedCell.colSpan = row.cells.length;
        expandedCell.style.padding = '0';
        expandedCell.style.overflow = 'visible';

        // Calculate the available width (viewport or container width minus padding)
        const tableWrapper = document.querySelector('.table-wrapper');
        const containerWidth = tableWrapper ? tableWrapper.offsetWidth : window.innerWidth;
        const maxContentWidth = containerWidth - 60; // Account for padding

        // Build vertical layout with a constraining wrapper
        const wrapper = document.createElement('div');
        wrapper.style.padding = '1.5rem';
        wrapper.style.maxWidth = `${maxContentWidth}px`;
        wrapper.style.width = '100%';
        wrapper.style.overflow = 'visible';
        wrapper.style.boxSizing = 'border-box';

        const gridContainer = document.createElement('div');
        gridContainer.className = 'expanded-content';

        cells.forEach((cell, index) => {
            if (headers[index]) {
                const headerText = headers[index].textContent.trim();

                const item = document.createElement('div');
                item.className = 'expanded-item';

                const label = document.createElement('div');
                label.className = 'expanded-label';
                label.textContent = headerText;

                const value = document.createElement('div');
                value.className = 'expanded-value';
                value.innerHTML = cell.innerHTML;

                item.appendChild(label);
                item.appendChild(value);
                gridContainer.appendChild(item);
            }
        });

        wrapper.appendChild(gridContainer);
        expandedCell.appendChild(wrapper);
        expandedRow.appendChild(expandedCell);

        // Insert after current row
        row.parentNode.insertBefore(expandedRow, row.nextSibling);

        // Update icon
        icon.textContent = '›';
        icon.style.transform = 'rotate(90deg)';
        row.classList.add('row-expanded');
    }
}
