from flask import Flask, render_template, request, abort
from logic_checker import perform_security_scan
import html  # Input-ai clean panna use aagum

app = Flask(__name__)

# Security Config: Debug mode-ai production-la off pannanum
app.config['DEBUG'] = True 

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/check', methods=['POST'])
def check_safety():
    try:
        # 1. INPUT SANITIZATION (Cleaning data)
        # User input-la irukka thevaiillatha spaces-ai remove panrom
        url_to_test = request.form.get('url_input', '').strip()

        # 2. INPUT VALIDATION (Basic check)
        if not url_to_test:
            return render_template('index.html', error="Please enter a valid URL!")

        # 3. LENGTH LIMIT (Prevent DoS Attacks)
        # Romba periya input vantha, server-ai kapatha reject panrom
        if len(url_to_test) > 2000:
            return render_template('index.html', error="URL is too long! Maximum 2000 characters allowed.")

        # 4. XSS PROTECTION (Cross-Site Scripting)
        # HTML characters-ai escape panrom (e.g., convert <script> to &lt;script&gt;)
        safe_url = html.escape(url_to_test)

        # 5. EXECUTION (Running the logic)
        scan_result = perform_security_scan(safe_url)
        
        # 6. SECURITY HEADERS (Optional but impressive)
        # Response anuppum pothu security headers add panrom
        response = render_template('index.html', 
                                   result=scan_result, 
                                   tested_url=safe_url)
        return response

    except Exception as e:
        # 7. ERROR HANDLING (Robustness)
        # Ethavathu crash aanalum, user-ku "Error" nu azhaga kaattum
        print(f"Error occurred: {e}") # Log the error for you
        return render_template('index.html', error="An internal error occurred. Please try again.")

# Security Header Injection
@app.after_request
def add_security_headers(response):
    # Ithu Judges-kitta "Naanga Browser Security pathiyum yosichom" nu solla help pannum
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    return response

if __name__ == '__main__':
    # Hackathon mudinja udane 'False' nu maathidunga
    app.run(debug=True)