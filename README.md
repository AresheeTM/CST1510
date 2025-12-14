[README.md](https://github.com/user-attachments/files/24150563/README.md)
=========================================================
Multi-Domain Intelligence Platform
Coursework: CST1510_Coursework_2_Comprehensive_Project_Guide_-_Multi-Domain_Intelligence_Platform
Author: Areshee Marimootoo
Student ID: M01069426
=========================================================

1. PROJECT OVERVIEW
-------------------
This project is a "Multi-Domain Intelligence Platform" implemented using Python and Streamlit. 
The platform provides interactive dashboards for Cybersecurity, IT Operations, and Data Science domains.
It includes role-based access control, interactive neon-themed UI panels, AI chatbot integration, CSV uploads, and data visualization.

The platform was designed to meet the following objectives:
- Display KPIs and visualizations for Cyber Incidents, IT Tickets, and Datasets.
- Provide a professional, interactive user interface with neon-glass panel effects.
- Implement secure authentication with role-based access.
- Enable CSV data uploads for dynamic dashboard updates.
- Include an AI chatbot for contextual assistance on each dashboard.

Supported Roles:
- Admin
- Cybersecurity
- Data Science
- IT Operations

Each role has access only to allowed pages.

---

2. PROJECT FEATURES
-------------------
1. **Secure Login System**
   - Users login using credentials stored securely with bcrypt hashing.
   - Session management ensures only authorized users can access restricted pages.

2. **Role-Based Access Control**
   - Admin: Access to all dashboards and user management.
   - Cybersecurity: Access to Cyber Incidents dashboard.
   - Data Science: Access to Datasets dashboard.
   - IT Operations: Access to IT Tickets dashboard.

3. **Interactive Dashboards**
   - **Cyber Incidents Dashboard**
     - KPIs: Total incidents, open/active, resolved/closed.
     - Charts: Severity distribution, status distribution, heatmaps, timelines.
     - Top reporters and incidents by hour.
     - Export to PDF functionality.
   - **IT Tickets Dashboard**
     - Ticket KPIs, status, priority, and timeline visualizations.
   - **Datasets Dashboard**
     - Visualizations and summaries of uploaded datasets.
   
4. **Drag-and-Drop Neon Constellation Panels**
   - Dashboard welcome messages appear in a draggable, interactive neon-glass panel.
   - Neon star constellation effect provides a visually engaging interface.
   - Panel is reusable across Cyber, IT, and Data dashboards.

5. **CSV Upload Functionality**
   - Each dashboard allows uploading CSV files via a drag-and-drop uploader.
   - Uploaded files are automatically saved and replace previous data.
   - Upload does not duplicate existing tables; only updates the dashboard data.

6. **AI Chatbot Integration**
   - Context-aware AI chatbot is available on each dashboard.
   - Provides guidance and information relevant to the dashboard domain.

7. **Sidebar Navigation**
   - Role-based navigation menu.
   - Logout button placed at the bottom, styled as circular neon pink.

---

3. SOFTWARE AND DEPENDENCY REQUIREMENTS
---------------------------------------
- Python 3.9 or higher
- Streamlit
- Pandas
- Numpy
- Plotly
- bcrypt
- pathlib
- Other packages included in `requirements.txt`.

---

4. FOLDER STRUCTURE
-------------------
My project is organized as follows:

CST1500/
│
├─ app/
│ ├─ data/
│ │ ├─ users.py
│ │ ├─ tickets.py
│ │ └─ incidents.py
│ ├─ pages/
│ │ ├─ cyber_incidents.py
│ │ ├─ it_tickets.py
│ │ └─ datasets.py
│ ├─ utils.py
│ ├─ ai_chatbot.py
│ └─ ai_sidebar.py
│
├─ DATA/
│ ├─ cyber_incidents.csv
│ ├─ it_tickets.csv
│ └─ datasets.csv
│
├─ reports/
│ └─ [Generated PDF reports]
│
├─ streamlit_app.py
├─ requirements.txt
└─ README.txt


---

5. INSTALLATION INSTRUCTIONS
----------------------------
1. Clone or download the project repository.
2. Ensure Python 3.9+ is installed.
3. Navigate to the project root directory.
4. Install required packages: pip install -r requirements.txt

5. Ensure the `DATA/` folder contains the relevant CSV files (`cyber_incidents.csv`, `it_tickets.csv`, `datasets.csv`).  
   If the files do not exist, upload them using the CSV uploader on the respective dashboards.

---

6. RUNNING THE APPLICATION
--------------------------
1.Create a folder(.streamlit); inside create a secrets.toml and insert Gemini_API_Key.
2. Navigate to the project root directory in your terminal/command prompt.
3. Run Streamlit: streamlit run streamlit_app.py

4. The platform will open in your default browser at `http://localhost:8501`.
5. Login using one of the pre-configured users (credentials stored in `app/data/users.py`):
   - Example:
     - Username: `admin`
     - Password: `admin123`
6. Navigate dashboards using the sidebar menu.

---

7. DASHBOARD USAGE
------------------
**Cyber Incidents Dashboard**
- Upload new CSV data via the drag-and-drop uploader.
- Toggle neon constellation panel for welcome message and aesthetics.
- Filter incidents by severity, status, date, and keywords.
- View KPIs and interactive charts.
- Export dashboard report as PDF.

**IT Tickets Dashboard**
- Similar functionality as Cyber Incidents but for IT tickets.
- Filter tickets by priority, status, or date.
- Interactive KPIs and charts.

**Datasets Dashboard**
- Upload CSV datasets to visualize data summaries.
- Interactive charts and KPIs update dynamically based on uploaded data.

**Logout**
- Click the neon pink circular button at the bottom of the sidebar to log out.

---

8. NOTES FOR THE LECTURER
--------------------------
- All pages enforce **role-based access**; attempting to access unauthorized pages will display an access denied message.
- Dashboard panels are **interactive and draggable**, enhancing user experience.
- CSV uploads dynamically refresh the dashboard without duplicating previous data.
- PDF reports include current KPIs and can be downloaded for review.

---

9. CONTACT / AUTHOR
-------------------
- Author: **Areshee Marimootoo**
- Student ID: **M01069426**
- Course: **CST1510**

=========================================================


