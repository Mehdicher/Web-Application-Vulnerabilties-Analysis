# Cybersecurity Analysis Project

## Overview
This project focuses on analyzing and securing a task management application built with Node.js, ensuring its reliability and protection against security threats. The first phase involves a thorough source code analysis to identify vulnerabilities such as authentication flaws, SQL/XSS injection risks, improper session handling, and inadequate input validation. Once these weaknesses are identified, robust security measures will be implemented, including strong authentication mechanisms, secure password storage (bcrypt), protection against CSRF and XSS attacks, and improved error handling and logging. Simultaneously, we will enhance the user interface by developing modern and interactive static pages in HTML, CSS, and Vanilla JavaScript, leveraging the Fetch API for smooth backend interactions. These pages include a login and registration system (login.html, register.html), a dashboard (dashboard.html) for users to add, view, and delete tasks, and a homepage (index.html) providing an overview of the application. Additionally, a detailed security report will be produced, documenting the identified vulnerabilities, their potential impact, and the corrective actions taken to mitigate them. The project will conclude with the delivery of a fully functional and secure version of the application, along with comprehensive documentation covering its architecture, security enhancements, and best practices. Through this structured approach, we aim to provide a robust, secure, and user-friendly task management solution while adhering to cybersecurity standards.

Your task is to examine the provided code, identify vulnerabilities, and propose improvements to enhance security and reliability.

## Application Features
- **User Registration and Login**: Users can register with a username and password, and log in to access protected features.
- **Task Management**: Authenticated users can add, view, and delete tasks.
- **Session Management**: The application uses session middleware to manage user sessions.
- **Static File Serving**: 
  - Unprotected files (`login.html`, `register.html`) are served from the `public` folder.
  - Protected files (`index.html`, `dashboard.html`) are served from the `private/protected` folder and require authentication.

## Structure
- **Public Routes**:
  - `POST /register`: Register a new user.
  - `POST /login`: Authenticate an existing user.
  - `GET /public/login.html`: Serve the login page.
  - `GET /public/register.html`: Serve the registration page.
- **Protected Routes**:
  - `GET /`: Redirect to the dashboard or login based on session status.
  - `GET /dashboard`: Serve the dashboard page for authenticated users.
  - `POST /add`: Add a task for the logged-in user.
  - `GET /tasks`: Retrieve tasks for the logged-in user.
  - `DELETE /tasks/:id`: Delete a task by ID.
  - `GET /logout`: Log out the current user.

## Your Task
1. **Analyze the Code**:
   - Review the codebase provided in the repository.
   - Identify all security vulnerabilities and areas where errors are not handled properly.

2. **Develop Static Files**:
   - Create the necessary HTML files for the `public` and `private/protected` folders:
     - `login.html`: A user-friendly login page.
     - `register.html`: A registration page with a form.
     - `index.html`: The main dashboard page for logged-in users.
     - `dashboard.html`: A page for managing tasks.
   - The dashboard should include two sections:
     - **Add Task Section**: A form to add new tasks.
     - **Task Display Section**: A table that lists all tasks retrieved from the server.
   - Use modern CSS to create a visually appealing layout and user experience.
   - Implement functionality using only vanilla JavaScript, the Fetch API, and DOM manipulation.

3. **Document Vulnerabilities and Errors**:
   - For each issue, explain the potential impact and suggest a solution to mitigate the problem.

4. **Submit a Report**:
   - Your report should include:
     - A list of identified vulnerabilities.
     - A list of unhandled error scenarios.
     - Proposed solutions for each issue.

## Deliverables
- The final project, including all developed files and the implemented functionalities.
- A detailed report of vulnerabilities and error scenarios.
- Developed static files (html and js) with well-designed layouts and CSS.
- A functional dashboard with task addition and display sections implemented using vanilla JavaScript.

## Notes
- This project is intentionally insecure. Do not deploy it in a production environment.
- Focus on analysis and understanding rather than implementing fixes immediately.

Good luck!

