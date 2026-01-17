const CONFIG = {
    API_BASE_URL: 'https://pulverable-kaydence-modular.ngrok-free.dev',
};

function getBaseHeaders() {
    return {
        'Content-Type': 'application/json',
        'ngrok-skip-browser-warning': 'true'
    };
}