# # import sys
# # from slack_sdk import WebClient
# # from slack_sdk.errors import SlackApiError
# #
# # # Replace with your bot's token
# # slack_token = "xoxb-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"  # Replace with your bot token
# # channel_id = "C080RQL464D"  # Replace with the actual channel ID
# # client = WebClient(token=slack_token)
# #
# #
# # def send_slack_notification(remote_ip, local_ip):
# #     try:
# #         response = client.chat_postMessage(
# #             channel=channel_id,
# #             text=f"Remote connection from IP: {remote_ip} to local PC with IP: {local_ip}"
# #         )
# #         print(f"Notification sent to Slack channel {channel_id}")
# #     except SlackApiError as e:
# #         print(f"Error sending message to Slack: {e.response['error']}")
# #
# #
# # if __name__ == "__main__":
# #     remote_ip = sys.argv[1]  # First argument: remote IP
# #     local_ip = sys.argv[2]  # Second argument: local IP
# #     send_slack_notification(remote_ip, local_ip)
#
#
# import sys
# import socket
# import subprocess
# from slack_sdk import WebClient
# from slack_sdk.errors import SlackApiError
#
# # Replace with your bot's token
# slack_token = "xoxb-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"  # Replace with your bot token
# channel_id = "C080RQL464D"  # Replace with the actual channel ID
# client = WebClient(token=slack_token)
#
#
# def get_local_ip():
#     """Fetch the local PC's IP address."""
#     try:
#         hostname = socket.gethostname()
#         local_ip = socket.gethostbyname(hostname)
#         return hostname, local_ip
#     except Exception as e:
#         print(f"Error fetching local IP: {e}")
#         return "Unknown"
#
#
# # def get_remote_details():
# #     """Fetch details about remote IP and username using 'query session'."""
# #     try:
# #         result = subprocess.run(args=['query', 'session'], capture_output=True, text=True, check=True)
# #         remote_ip, remote_username = None, None
# #         for line in result.stdout.splitlines():
# #             if "rdp-tcp" in line and "Active" in line:
# #                 columns = line.split()
# #                 session_name = columns[1]
# #                 remote_username = columns[0]
# #                 session_id = columns[2]
# #
# #                 # Get remote IP using the session ID
# #                 netstat_result = subprocess.run(['netstat', '-n'], capture_output=True, text=True, check=True)
# #                 for netstat_line in netstat_result.stdout.splitlines():
# #                     if f"{session_name}" in netstat_line:
# #                         remote_ip = netstat_line.split()[2].split(":")[0]
# #                         break
# #
# #                 if remote_ip:
# #                     return remote_ip, remote_username
# #
# #         return "Unknown", remote_username or "Unknown"
# #     except subprocess.CalledProcessError as e:
# #         print(f"Error fetching remote details: {e}")
# #         return "Unknown", "Unknown"
# def get_remote_details():
#     """Fetch details about remote IP and username using 'qwinsta' and 'netstat'."""
#     try:
#         # Fetch active sessions
#         qwinsta_result = subprocess.run(['qwinsta'], capture_output=True, text=True, check=True)
#         session_info = None
#
#         # Parse qwinsta output
#         for line in qwinsta_result.stdout.splitlines():
#             if "rdp-tcp" in line and "Active" in line:
#                 columns = line.split()
#                 remote_username = columns[0]  # Username
#                 session_id = columns[2]  # Session ID
#                 session_info = f"rdp-tcp#{session_id}"
#                 break
#
#         if not session_info:
#             return "Unknown", "Unknown"
#
#         # Fetch network connections using netstat
#         netstat_result = subprocess.run(['netstat', '-n'], capture_output=True, text=True, check=True)
#
#         # Find the remote IP linked to the session
#         remote_ip = None
#         for netstat_line in netstat_result.stdout.splitlines():
#             if session_info in netstat_line:
#                 # Extract remote IP (format: foreign address -> <IP>:<port>)
#                 remote_ip = netstat_line.split()[2].split(":")[0]
#                 break
#
#         return remote_ip or "Unknown", remote_username
#     except subprocess.CalledProcessError as e:
#         print(f"Error fetching remote details: {e}")
#         return "Unknown", "Unknown"
#
#
# def send_slack_notification(remote_ip, remote_username, local_ip, local_user):
#     """Send a notification to Slack."""
#     try:
#         response = client.chat_postMessage(
#             channel=channel_id,
#             text=f"📡 **Remote Connection Alert**\n"
#                  f"👤 Remote User: {local_user}\n"
#                  f"🌐 Remote IP: {local_ip}\n"
#                  f"👤 Local PC User: {remote_username}\n"
#                  f"💻 Local PC IP: {remote_ip}"
#         )
#         print(f"Notification sent to Slack channel {channel_id}")
#     except SlackApiError as e:
#         print(f"Error sending message to Slack: {e.response['error']}")
#
#
# if __name__ == "__main__":
#     local_username, local_ip = get_local_ip()
#     remote_ip, remote_username = get_remote_details()
#     print(local_ip, local_username)
#     print(remote_ip, remote_username)
#     res = subprocess.run('netstat', capture_output=True)
#     print(res)
#     # send_slack_notification(remote_ip=remote_ip, remote_username=remote_username, local_ip=local_ip, local_user=local_username)
