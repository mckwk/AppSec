// Configuration file for frontend
const CONFIG = {
    API_BASE_URL: 'https://pulverable-kaydence-modular.ngrok-free.dev',
};

// Helper function to get base headers for API requests
// Includes ngrok-skip-browser-warning to bypass ngrok's interstitial page
function getBaseHeaders() {
    return {
        'Content-Type': 'application/json',
        'ngrok-skip-browser-warning': 'true'
    };
}