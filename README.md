# HelloKittyCMS

HelloKittyCMS is a simple content management system built with Flask for the backend and vanilla JavaScript for the frontend. This project includes user registration, email activation, and a styled user interface.


## Prerequisites

- Python 3.8+
- A MailerSend account for email services
- ngrok to serve the API

## Setup Instructions

### Backend Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/mckwk/AppSec.git
   cd AppSec/backend
   ```

2. **Create a virtual environment:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up the environment variables:**
   - Copy the `.env` file and update the values as needed:
     ```
     SECRET_KEY=your_secret_key
     MAILERSEND_API_KEY=your_mailersend_api_key
     DATABASE_URI=sqlite:///path_to_your_database
     ACTIVATION_SALT=email-activation
     MAILERSEND_FROM_EMAIL=your_email@example.com
     FLASK_DEBUG=True
     ```

5. **Run the application:**
   ```bash
   python app.py
   ```
   The application will be available at `http://127.0.0.1:5000/`.
   To expose the API to the internet, you can use ngrok with command:
    ```bash
    ngrok http 5000
    ``` 

### Frontend Setup

1. **Navigate to the frontend directory:**
   ```bash
   cd ../frontend
   ```

2. **Set up the frontend configuration:**
   - Copy `config.js.example` to `config.js` and update the `API_BASE_URL`:
     ```javascript
     const CONFIG = {
         API_BASE_URL: 'http://127.0.0.1:5000',
     };
     ```

3. **Open `index.html` in a browser or deploy to vercel.**

## Features

- User registration with email activation
- Styled frontend and backend templates
- Secure password hashing with bcrypt
- SQLite database for user data

