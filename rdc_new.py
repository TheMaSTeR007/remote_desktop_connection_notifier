# import win32evtlog
# import socket
# import os
# from slack_sdk import WebClient
# from slack_sdk.errors import SlackApiError
#
# # Slack Bot Token (Replace with your bot token)
# SLACK_BOT_TOKEN = "    SLACK_BOT_TOKEN = "xoxb-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX""  # Replace with your Slack bot token
# SLACK_CHANNEL = "C080RQL464D"  # Replace with the channel to send messages to
#
# # Initialize Slack Client
# slack_client = WebClient(token=SLACK_BOT_TOKEN)
#
#
# def send_slack_message(channel, message):
#     """Send a message to Slack using the Slack SDK."""
#     try:
#         response = slack_client.chat_postMessage(channel=channel, text=message)
#         if response["ok"]:
#             print("Message sent to Slack successfully!")
#         else:
#             print(f"Failed to send message: {response['error']}")
#     except SlackApiError as e:
#         print(f"Error sending message to Slack: {e.response['error']}")
#
#
# def get_remote_desktop_logins():
#     """Monitor the Windows Event Log for RDP connections."""
#     server = "localhost"
#     log_type = "Security"
#     log_handle = win32evtlog.OpenEventLog(server, log_type)
#
#     flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
#     events = win32evtlog.ReadEventLog(log_handle, flags, 0)
#
#     for event in events:
#         if event.EventID == 4624:  # Logon Event
#             try:
#                 event_data = event.StringInserts
#                 logon_type = int(event_data[8])  # Logon Type is the 9th string (index 8)
#
#                 if logon_type == 10:  # Remote Desktop Connection
#                     local_ip = socket.gethostbyname(socket.gethostname())
#                     local_username = os.getlogin()
#                     remote_ip = event_data[18]  # Source IP is the 19th string (index 18)
#                     remote_username = event_data[5]  # Remote username is the 6th string (index 5)
#
#                     # Print to console
#                     print(local_ip, local_username)
#                     print(remote_ip, remote_username)
#
#                     # Send to Slack
#                     message = (
#                         f"New RDP connection detected!\n"
#                         f"Local IP: {local_ip}\n"
#                         f"Local Username: {local_username}\n"
#                         f"Remote IP: {remote_ip}\n"
#                         f"Remote Username: {remote_username}"
#                     )
#                     send_slack_message(SLACK_CHANNEL, message)
#             except Exception as e:
#                 print(f"Error processing event: {e}")
#
#
# if __name__ == "__main__":
#     print("Monitoring RDP connections...")
#     get_remote_desktop_logins()


import subprocess
import requests
import socket
import os
import re
import psutil

# hostname = socket.gethostname()
# ip_address = socket.gethostbyname(hostname)
# print(f"IP Address: {ip_address}", f"hostname: {hostname}")

# response = requests.get('https://api.ipify.org?format=json')
# public_ip = response.json()['ip']
# print(f"Public IP Address: {public_ip}")


# # Run the ipconfig command
# result = subprocess.run(args=['ipconfig'], capture_output=True, text=True)
# output = result.stdout
# # Extract IPv4 addresses using a regular expression
# ipv4_addresses = re.findall(pattern=r"IPv4 Address.*?: (\d+\.\d+\.\d+\.\d+)", string=output)
#
# print("IPv4 Addresses:")
# print(ipv4_addresses[-1])

user_dict = dict()
# Get the username of the currently logged-in user
username = os.getlogin()
user_dict['username'] = username
# Get network interface details
addresses = psutil.net_if_addrs()
for interface, addr_list in addresses.items():
    for addr in addr_list:
        if addr.family == socket.AF_INET:  # Check for IPv4
            # Get IPv4 addresses for each interface
            user_dict[interface] = addr.address

print(user_dict)

# import socket
# import wmi
# from slack_sdk import WebClient
# from slack_sdk.errors import SlackApiError
#
# # Slack configuration
# SLACK_TOKEN = "xoxb-your-slack-bot-token"  # Replace with your bot token
# SLACK_CHANNEL = "#general"  # Replace with your Slack channel name
#
#
# # Function to send a Slack message
# def send_slack_message(ip_address, usernames):
#     client = WebClient(token=SLACK_TOKEN)
#     try:
#         message = f"🚨 New Remote Connection Detected!\n"
#         message += f"🔑 IP Address: {ip_address}\n"
#         if usernames:
#             message += f"👤 Usernames: {', '.join(usernames)}"
#         else:
#             message += "👤 Usernames: Could not detect."
#         client.chat_postMessage(channel=SLACK_CHANNEL, text=message)
#         print("Slack message sent!")
#     except SlackApiError as e:
#         print(f"Failed to send Slack message: {e.response['error']}")
#
#
# # Function to get remote usernames
# def get_remote_users():
#     wmi_client = wmi.WMI()
#     sessions = wmi_client.Win32_LogonSession()
#     users = []
#     for session in sessions:
#         if session.LogonType == 10:  # Remote interactive session
#             user_refs = session.references("Win32_LoggedOnUser")
#             for user in user_refs:
#                 users.append(user.Antecedent.Name)
#     return users
#
#
# # Function to listen for incoming connections
# def start_server():
#     HOST = ''  # Listen on all interfaces
#     PORT = 65432  # Open port
#     print(f"Listening on port {PORT}...")
#     with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
#         server_socket.bind((HOST, PORT))
#         server_socket.listen()
#         while True:
#             conn, addr = server_socket.accept()  # Accept incoming connection
#             with conn:
#                 ip_address = addr[0]  # Remote IP address
#                 print(f"Connected by: {ip_address}")
#                 usernames = get_remote_users()  # Get remote usernames
#                 print(f"Remote Users: {', '.join(usernames) if usernames else 'None'}")
#                 # Send Slack notification
#                 send_slack_message(ip_address, usernames)
#
#
# # Start the server
# if __name__ == "__main__":
#     start_server()


import socket
import wmi


def get_local_ip():
    """Get the local machine's IP address."""
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    return local_ip


def get_remote_ip_and_user():
    """Get remote IP and username from active RDP sessions."""
    wmi_client = wmi.WMI()
    sessions = wmi_client.Win32_LogonSession()
    remote_info = []

    for session in sessions:
        if session.LogonType == 10:  # Type 10 = Remote Interactive Session
            user_refs = session.references("Win32_LoggedOnUser")
            for user in user_refs:
                username = user.Antecedent.Name
                # Fetch the remote address from the session
                remote_ip = session.references("Win32_IP4RouteTable")[0].NextHop if session.references("Win32_IP4RouteTable") else "Unknown IP"
                remote_info.append((username, remote_ip))
    return remote_info


if __name__ == "__main__":
    local_ip = get_local_ip()
    remote_sessions = get_remote_ip_and_user()

    print(f"Local PC IP Address: {local_ip}")
    if remote_sessions:
        for username, remote_ip in remote_sessions:
            print(f"Remote User: {username}, Remote IP: {remote_ip}")
    else:
        print("No active RDP sessions found.")
