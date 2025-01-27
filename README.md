Here's a README for your project:

---

# GrubBug: Vulnerable Web Application for Cybersecurity Education

GrubBug is a learning, teaching, and evaluation tool designed to help cybersecurity students understand application security vulnerabilities. It provides practical, hands-on experience with web vulnerabilities using both secure and insecure modes. GrubBug simulates a food delivery service and is inspired by projects like JuiceShop, bWAPP, and DVWA but includes modern and dynamic features like challenge randomization and guided learning.

## Features

### Current Vulnerability Demonstrations
1. **Broken Access Control (A01-2021)**
   - Role-Based Access Control (RBAC) violations
   - Direct Object Reference (IDOR) vulnerabilities
   - API abuse (e.g., unauthorized DELETE)
   - Direct file access flaws
   - Mass assignment vulnerabilities

2. **Cryptographic Failures (A02-2021)**
   - Insecure encryption (e.g., weak keys, predictable patterns)
   - Missing encryption
   - Demonstration of brute force feasibility and practical consequences of poor cryptographic choices

### Secure/Insecure Mode
GrubBug operates in two modes:
- **Secure Mode**: Implements best practices to prevent vulnerabilities.
- **Insecure Mode**: Allows vulnerabilities to be explored and exploited for educational purposes.

### Dynamic Examples
- Live updates: Changes in backend data (e.g., file creation/deletion) are reflected in the UI.
- Interactive demonstrations: Users can directly manipulate data (e.g., modify profile fields, request encrypted messages) and see the results of their actions.

### Instructor Tools (Planned)
- Monitor student progress
- Configure challenges and track performance
- Generate randomized exam scenarios

## Installation

### Requirements
- Python 3.9 or higher
- Required Python libraries:
  ```
  Flask
  Flask-Login
  Flask-SQLAlchemy
  PyCryptodome
  bcrypt
  python-dotenv
  ```

### Setup
1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/grubbug.git
   cd grubbug
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Set up the environment:
   - Create a `.env` file with the following variables:
     ```
     SECRET_KEY=your-secret-key
     DATABASE_URL=sqlite:///grubbug.db
     ```
   - Optionally configure SAML integration by adding `SAML_PATH`.

4. Initialize the database:
   ```bash
   python app.py
   ```

5. Run the app:
   ```bash
   flask run
   ```

6. Access the app in your browser at `http://127.0.0.1:5000`.

## Directory Structure
```
grubbug/
│
├── static/                   # Static files (CSS, JS, images)
├── templates/                # HTML templates
├── demo-files/               # Live demo files for access control examples
├── app.py                    # Main application logic
├── requirements.txt          # Python dependencies
└── README.md                 # Project documentation
```

## License
This project is licensed under the MIT License. See the LICENSE file for details.
