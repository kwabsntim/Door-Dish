import smtplib
import os
from dotenv import load_dotenv

load_dotenv()

try:
    with smtplib.SMTP_SSL(os.getenv('MAIL_SERVER'), 465) as server:
        server.login(
            os.getenv('MAIL_USERNAME'),
            os.getenv('MAIL_PASSWORD').replace(" ", "")
        )
        print("SMTP Connection Successful!")
except Exception as e:
    print(f"Connection failed: {e}")