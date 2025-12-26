/**
 * Dark Mode Toggle Functionality
 * Handles dark mode switching and persistence
 */

const moonIcon = "https://img.icons8.com/ios-filled/50/ffffff/moon-symbol.png";
const sunIcon = "https://img.icons8.com/ios-filled/50/ffffff/sun.png";

function toggleDarkMode() {
    document.body.classList.toggle("dark-mode");
    const isDark = document.body.classList.contains("dark-mode");
    localStorage.setItem("darkMode", isDark);
    updateDarkModeIcon();
}

function updateDarkModeIcon() {
    const darkModeIcon = document.getElementById("darkModeIcon");
    if (!darkModeIcon) return;

    if (document.body.classList.contains("dark-mode")) {
        darkModeIcon.src = sunIcon;
        darkModeIcon.alt = "Light Mode";
    } else {
        darkModeIcon.src = moonIcon;
        darkModeIcon.alt = "Dark Mode";
    }
}

function applyDarkMode() {
    // Check localStorage first, then fall back to system preference
    const savedMode = localStorage.getItem("darkMode");
    const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;

    if (savedMode === "true" || (savedMode === null && prefersDark)) {
        document.body.classList.add("dark-mode");
    }
    updateDarkModeIcon();
}

// Listen for system theme changes
if (window.matchMedia) {
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', e => {
        if (localStorage.getItem("darkMode") === null) {
            if (e.matches) {
                document.body.classList.add("dark-mode");
            } else {
                document.body.classList.remove("dark-mode");
            }
            updateDarkModeIcon();
        }
    });
}

// Apply dark mode on page load
applyDarkMode();
