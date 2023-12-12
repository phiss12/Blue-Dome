# Code Execution Instructions

This document provides instructions on how to run the code for displaying images from an Excel file in a web gallery format.



## Running the Code
1. Navigate to the project directory using the terminal or command prompt and pip install flask, pandas.
2. Install the required packages:
   ```
   pip install Flask sqlite3 pandas Werkzeug itsdangerous Flask-Login Flask-Mail 
   ```
3. Execute the following command to run the Flask application:
   ```
   python app.py
   ```
4. Open a web browser and enter the following URL: `http://localhost:5000` (or the URL provided by Flask).
5. You will be directed to the home page where you can select an Excel file from the dropdown list.
6. After selecting the file, click the "Submit" button to display the images in a gallery format.
7. Use the left and right arrow buttons to navigate between the images.
