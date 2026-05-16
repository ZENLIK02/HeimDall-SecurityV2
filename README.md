#  AI-ASOC: Automated Security Orchestration & Correlation

A centralized AI system acting as an Automated Pentester. It is designed to filter out False Positives from SAST (Static Application Security Testing) alerts and automatically validate real vulnerabilities with empirical evidence. 

Developed for the **Leagues of Code AI & Cybersecurity Hackathon**.

---

##  Prerequisites
Before you begin, ensure you have met the following requirements:
* **Python 3.8+**
* **Docker Desktop** (required to run the vulnerable target environment)
* **OpenAI API Key** (must have available billing credits)
---

##  Installation

**1. Clone the repository:**
`git clone <your_github_link_here>`
`cd AI-ASOC-Hackathon`

**2. Create and activate a Virtual Environment:**
* **Windows:**
  `python -m venv asoc_env`
  `asoc_env\Scripts\activate`
* **Mac/Linux:**
  `python3 -m venv asoc_env`
  `source asoc_env/bin/activate`

**3. Install required libraries:**
`pip install requests openai streamlit semgrep`

**4. Configure the API Key:**
Open `app.py` and `dast_executor.py` in your code editor and insert your OpenAI API Key into the designated variable:
`api_key = "sk-proj-xxxxxxxxxxxxxxxxxxxxxxxx"`

---
##  How to Run (Demo Flow)

Testing the system consists of 3 main steps:

### Step 1: Start the Target Environment
We use OWASP Juice Shop as our vulnerable target application. Open a new Command Prompt and run:
`docker run --rm -p 3000:3000 bkimminich/juice-shop`
*(The target application will be running at `http://localhost:3000`)*

### Step 2: Execute Source Code Scan (SAST)
Go back to your project terminal (where `(asoc_env)` is activated) and run a Semgrep scan against the Juice Shop source code folder:
*(Note: You must download the Juice Shop source code to your local machine first)*
`semgrep scan --config auto --json -o sast_results.json <path_to_juice_shop_folder>`
Once completed, a `sast_results.json` file will be generated in your project directory.

### Step 3: Launch the Dashboard (AI Orchestration & DAST)
Run the following command to start the Streamlit web application:
`streamlit run app.py`

* The web interface will display the SAST scan results.
* Click the **" Run AI-ASOC (Analyze & Exploit)"** button.
* The AI will read the vulnerable code, generate an exploit payload, and fire it at the target system (DAST). It will then analyze the HTTP response and declare whether the vulnerability is a **True Positive** or **False Positive**.

---

##  Custom Target Testing (Bring Your Own Code)

If you want to use the AI-ASOC system to test your own application or source code, follow these steps:

**1. Prepare the Target Application:**
* Our AI requires a "live target" to execute payloads.
* Run your application locally (e.g., start your NodeJS or Python Flask server at `http://localhost:8080`).

**2. Run SAST on Your Custom Code:**
Use Semgrep to scan your project directory and generate the vulnerability map. **You must name the output file exactly as the system expects**:
`semgrep scan --config auto --json -o sast_results.json <path_to_your_project_folder>`
*(Ensure the new `sast_results.json` overwrites the existing one in the `AI-ASOC-Hackathon` folder)*

**3. Modify the AI Prompt:**
Open `app.py` (around line 46) and change the target URL from the default Juice Shop (`localhost:3000`) to your application's URL (`localhost:8080`):

**Before:**
`{"role": "system", "content": "You are a DAST Payload Generator... (Always prefix URL with http://localhost:3000)..."}`

**After (Assuming your app runs on port 8080):**
`{"role": "system", "content": "You are a DAST Payload Generator... (Always prefix URL with http://localhost:8080)..."}`

**4. Execute:**
Run `streamlit run app.py` again. The system will read the new JSON file, and the AI will attempt to generate a targeted payload to exploit your custom application!

---
*Developed by: บังมาเหนือผมเหลือไร*
