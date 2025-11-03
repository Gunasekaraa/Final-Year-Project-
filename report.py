import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
import pandas as pd
import logging
import io

# Ensure logging is set up
logging.basicConfig(
    level=logging.DEBUG,
    filename="app.log",
    filemode="a",
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def send_vulnerability_report(recipient_email, df, email_sender, email_password, smtp_server, smtp_port, oem="Unknown"):
    try:
        # Ensure the DataFrame has the expected columns
        if df is None or df.empty:
            logging.error("DataFrame is None or empty.")
            return False, "No data available to generate the report."

        logging.info(f"Columns in DataFrame: {df.columns.tolist()}")
        logging.info(f"DataFrame dtypes:\n{df.dtypes}")
        logging.info(f"DataFrame head:\n{df.head().to_string()}")

        # Replace NaN or empty values with "N/A" to ensure clean CSV output
        df = df.fillna("N/A").replace("", "N/A")
        logging.info(f"Unique values in published_date after filling NaN: {df['published_date'].unique().tolist() if 'published_date' in df.columns else 'N/A'}")

        # Convert DataFrame to CSV string
        csv_buffer = io.StringIO()
        df.to_csv(csv_buffer, index=False)
        csv_data = csv_buffer.getvalue()
        csv_buffer.close()

        # Set up the email
        msg = MIMEMultipart()
        msg["From"] = email_sender
        msg["To"] = recipient_email
        msg["Subject"] = f"Vulnerability Report - {oem}"

        # Add a simple email body
        body = f"Dear recipient,\n\nAttached is the vulnerability report for {oem}.\n\nBest regards,\nYour Vulnerability Tracker"
        msg.attach(MIMEText(body, "plain"))

        # Attach the CSV file
        csv_attachment = MIMEApplication(csv_data, _subtype="csv")
        csv_attachment.add_header("Content-Disposition", "attachment", filename=f"vulnerability_report_{oem}.csv")
        msg.attach(csv_attachment)

        # Send the email
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(email_sender, email_password)
            server.sendmail(email_sender, recipient_email, msg.as_string())

        return True, "Report sent successfully as CSV attachment!"
    except Exception as e:
        logging.error(f"Failed to send report: {str(e)}")
        return False, f"Failed to send report: {str(e)}"