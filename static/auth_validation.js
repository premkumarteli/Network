// auth_validation.js

document.addEventListener('DOMContentLoaded', function() {
    const loginForm = document.querySelector('form[action="{{ url_for(\'login_page\') }}"]');
    const registerForm = document.querySelector('form[action="{{ url_for(\'register_page\') }}"]');

    function cleanAndSubmit(event) {
        // Prevent default submission first
        event.preventDefault();

        const form = event.target;
        const formData = new FormData(form);

        // Trim whitespace from all text input fields to prevent login/hash mismatch errors
        for (const [key, value] of formData.entries()) {
            if (typeof value === 'string') {
                form.elements[key].value = value.trim();
            }
        }
        
        // Re-submit the form after cleaning
        form.submit();
    }

    if (loginForm) {
        loginForm.addEventListener('submit', cleanAndSubmit);
    }
    if (registerForm) {
        registerForm.addEventListener('submit', cleanAndSubmit);
    }
});