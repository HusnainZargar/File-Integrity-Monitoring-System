from flask import Flask, render_template_string
from .utils import get_logs

app = Flask(__name__)

LOGS_HTML = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>FIM Logs</title>
    <style>
        body { 
            font-family: Arial, sans-serif; 
            background-color: #f4f4f4; 
            margin: 20px; 
            color: #333; 
        }
        h1 { 
            text-align: center; 
            color: #007bff; 
        }
        table { 
            width: 100%; 
            border-collapse: collapse; 
            margin-top: 20px; 
            background-color: white; 
            box-shadow: 0 2px 4px rgba(0,0,0,0.1); 
        }
        th, td { 
            border: 1px solid #ddd; 
            padding: 12px; 
            text-align: left; 
        }
        th { 
            background-color: #007bff; 
            color: white; 
        }
        tr:nth-child(even) { 
            background-color: #f9f9f9; 
        }
        p { 
            text-align: center; 
            margin-top: 20px; 
            font-style: italic; 
        }
    </style>
</head>
<body>
    <h1>File Integrity Logs</h1>
    <table>
        <tr><th>Timestamp</th><th>Message</th></tr>
        {% for log in logs %}
        <tr><td>{{ log.timestamp }}</td><td>{{ log.message }}</td></tr>
        {% endfor %}
    </table>
    <p>Refresh to update.</p>
    <footer style="text-align: center; margin-top: 20px; color: gray;">v0.1.0-alpha</footer>
</body>
</html>
"""

@app.route('/logs')
def show_logs():
    logs = get_logs()
    return render_template_string(LOGS_HTML, logs=logs)
