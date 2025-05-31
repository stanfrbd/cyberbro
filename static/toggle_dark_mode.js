const moonIcon = "https://img.icons8.com/ios-filled/50/ffffff/moon-symbol.png";
const sunIcon = "https://img.icons8.com/ios-filled/50/ffffff/sun.png";

function toggleDarkMode() {
    document.body.classList.toggle("dark-mode");
    localStorage.setItem("darkMode", document.body.classList.contains("dark-mode"));
    updateDarkModeIcon();
}

function updateDarkModeIcon() {
    const darkModeIcon = document.getElementById("darkModeIcon");
    if (document.body.classList.contains("dark-mode")) {
        darkModeIcon.src = sunIcon;
        darkModeIcon.alt = "Light Mode";
    } else {
        darkModeIcon.src = moonIcon;
        darkModeIcon.alt = "Dark Mode";
    }
}

function applyDarkMode() {
    if (localStorage.getItem("darkMode") === "true") {
        document.body.classList.add("dark-mode");
    }
    updateDarkModeIcon();
}

applyDarkMode();
