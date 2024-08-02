import pandas as pd
import pywhatkit as kit
import time

# Load the Excel file
excel_file_path = r"C:/Users/aryan/OneDrive/Desktop/Contacts.csv.xlsx"  # Change to your file path
df = pd.read_excel(excel_file_path)

# Function to send WhatsApp messages
def send_whatsapp_message(phone_number, message, hour, minute):
    try:
        # Use pywhatkit to send the message
        # Parameters: phone number (with country code), message, hour, minute
        kit.sendwhatmsg(phone_number, message, hour, minute)
        print(f"Message sent to {phone_number}")
    except Exception as e:
        print(f"Failed to send message to {phone_number}: {e}")

# Get current time
current_time = time.localtime()
time_hour = current_time.tm_hour
time_minute = current_time.tm_min + 2  # Schedule message 2 minutes ahead

# Adjust time to handle overflow of minutes
if time_minute >= 60:
    time_minute -= 60
    time_hour += 1
    if time_hour >= 24:
        time_hour = 0

# Loop through the contacts and send messages
for index, row in df.iterrows():
    full_name = row['Full Name']
    phone_number = row['WhatsApp Number']
    # Convert the phone number to string and add the country code (assuming +91 for India)
    phone_number_str = f"+91{str(phone_number)}"
    
    # Compose the message
    message = "Hello, This is Aryan Parashar from Shadowfox, I'll be guiding you through our research mentorship program starting first with an indroductory meet. We are available on Monday to Friday post 7PM, kindly let me know your suitable date and time to schedule the meet. Regards"
    
    
    # Send the message
    send_whatsapp_message(phone_number_str, message, time_hour, time_minute)
    
    # Increment the scheduled time for the next message
    time_minute += 1
    if time_minute >= 60:
        time_minute -= 60
        time_hour += 1
        if time_hour >= 24:
            time_hour = 0

    # Wait a little before scheduling the next message to avoid sending too fast
    time.sleep(30)  # Wait for 30 seconds before sending the next message
