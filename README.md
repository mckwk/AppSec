# HelloKittyCMS

A secure content management platform with user authentication, MFA, and content publishing.

## Quick Start (Docker)

### Prerequisites
- [Docker](https://docs.docker.com/get-docker/) & [Docker Compose](https://docs.docker.com/compose/install/)

### Setup

1. **Clone and configure:**
   ```bash
   git clone -b dockerized https://github.com/mckwk/AppSec
   cd AppSec
   cp .env.example .env
   ```

2. **Edit `.env`** - Set your passwords:
   ```env
   MYSQL_ROOT_PASSWORD=your_root_password
   MYSQL_PASSWORD=your_db_password
   SECRET_KEY=your_secret_key
   PEPPER=your_pepper_value
   DEFAULT_ADMIN_EMAIL=admin@example.com
   DEFAULT_ADMIN_PASSWORD=YourAdminPass123!
   ```
   
   > **Note:** Everything else is optional. Actually, everything is optional if you really don't care. If `MAILERSEND_API_KEY` is empty, activation links print to the backend console.

3. **Start:**
   ```bash
   docker compose up -d
   ```

4. **Open:** http://localhost



