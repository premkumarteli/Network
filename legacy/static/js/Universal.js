// Universal.js - Handles global UI logic

// Page Transitions
document.addEventListener('DOMContentLoaded', () => {
    // Initialize sidebar state
    const sidebar = document.getElementById('sidebar');
    const isCollapsed = localStorage.getItem('sidebarCollapsed') === 'true';
    if (isCollapsed) {
        sidebar.classList.add('collapsed');
        updateSidebarIcon(true);
    }
    // Theme code removed
});

function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    sidebar.classList.toggle('collapsed');

    const isCollapsed = sidebar.classList.contains('collapsed');
    localStorage.setItem('sidebarCollapsed', isCollapsed);
    updateSidebarIcon(isCollapsed);
}

function updateSidebarIcon(collapsed) {
    const icon = document.getElementById('sidebar-toggle-icon');
    if (collapsed) {
        icon.classList.remove('ri-arrow-left-s-line');
        icon.classList.add('ri-arrow-right-s-line');
    } else {
        icon.classList.remove('ri-arrow-right-s-line');
        icon.classList.add('ri-arrow-left-s-line');
    }
}

// Add active class to current nav item (fallback if server-side fails)
const currentPath = window.location.pathname;
document.querySelectorAll('.nav-item').forEach(link => {
    if (link.getAttribute('href') === currentPath) {
        link.classList.add('active');
    }
});
