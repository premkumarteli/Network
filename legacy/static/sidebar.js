const sidebar = document.getElementById("sidebar");
const toggleBtn = document.getElementById("toggleBtn");
const mainContent = document.getElementById("main-content");
const navLinks = document.getElementById("navLinks");
const logoText = document.getElementById("logoText");

// --- 1. Sidebar Toggle Logic ---
toggleBtn.onclick = () => {
    sidebar.classList.toggle("collapsed");
    navLinks.classList.toggle("collapsed");
    logoText.classList.toggle("collapsed");
    mainContent.classList.toggle("shifted");
};

// --- 2. Active Link Highlighting Logic ---

// Get the current page name from the URL path (e.g., 'dashboard', 'devices', 'vpn')
// Handle the root path ('/') which resolves to an empty string or 'index.html'
let currentPage = window.location.pathname.split("/").pop();
if (currentPage === "") {
    // Assuming root path ("/") should highlight the Dashboard link
    currentPage = "dashboard"; 
}

// Iterate through all navigation links and add the 'active' class to the matching link
document.querySelectorAll("#navLinks a").forEach(link => {
    // Extract the page name from the link's HREF (e.g., "devices_page" -> "devices")
    let linkPath = link.getAttribute("href").split("/").pop().split("_")[0];
    
    // Correctly handle the special case where Flask creates a URL ending in just the name,
    // or if the URL is mapped directly to the function name.
    if (linkPath === currentPage || link.textContent.toLowerCase().includes(currentPage)) {
        link.classList.add("active");
    }
});