// Theme switching logic

function applyTheme(theme) {
    const body = document.getElementById("theme-body");
    body.classList.remove("light-mode", "dark-mode", "astro-mode");
    if (theme === "dark") body.classList.add("dark-mode");
    else if (theme === "astro") body.classList.add("astro-mode");
    else body.classList.add("light-mode");
    localStorage.setItem("theme", theme);
}

// Attach event listeners
document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll(".theme-option").forEach(el => {
        el.addEventListener("click", () => {
            applyTheme(el.dataset.theme);
        });
    });

    // Load saved theme
    const saved = localStorage.getItem("theme") || "light";
    applyTheme(saved);
});
