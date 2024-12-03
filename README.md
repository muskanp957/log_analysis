# Log Analysis Project

## **Overview**
This project processes web server logs to extract and analyze key information. It demonstrates proficiency in file handling, string manipulation, and data analysis using Python.

The script performs the following tasks:
1. Counts the number of requests made by each IP address.
2. Identifies the most frequently accessed endpoint.
3. Detects suspicious activities (e.g., failed login attempts exceeding a threshold).

---

## **Features**
1. **Requests Per IP Address**:
   - Counts the number of requests made by each IP address.
   - Displays the results in descending order.

2. **Most Frequently Accessed Endpoint**:
   - Analyzes the log to find the most accessed resource (e.g., `/home`, `/login`).
   - Outputs the resource name and the number of times it was accessed.

3. **Suspicious Activity Detection**:
   - Detects brute force attempts by counting failed login attempts (`401` status code).
   - Flags IPs exceeding a configurable threshold (default: 10 attempts).

4. **CSV Export**:
   - Saves results to a CSV file for further analysis.

---

## **How to Run the Project**
Follow these steps to execute the project:

### 1. **Set Up Your Environment**
   - Ensure Python is installed (`python --version`).
   - Install any required dependencies (if applicable).

### 2. **Download the Code**
   - Clone the repository:
     ```bash
     git clone https://github.com/muskanp957/log-analysis.git
     ```
   - Navigate to the project folder:
     ```bash
     cd log-analysis
     ```

### 3. **Prepare the Log File**
   - Place the log file (`sample.log`) in the project directory.

### 4. **Run the Script**
   - Execute the script:
     ```bash
     python log_analysis.py
     ```

### 5. **View the Results**
   - The script outputs results to the terminal and saves them in a CSV file:
     - **CSV File**: `log_analysis_results.csv`

---

## **Output Example**
### **Terminal Output**
```plaintext
IP Address           Request Count
203.0.113.5          8
198.51.100.23        8
192.168.1.1          7
10.0.0.2             6
192.168.1.100        5

Most Frequently Accessed Endpoint:
/login (Accessed 13 times)

Suspicious Activity Detected:
No suspicious activity detected.

Results saved to log_analysis_results.csv.
