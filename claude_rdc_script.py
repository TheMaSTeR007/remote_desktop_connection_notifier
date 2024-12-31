import socket
import os
import psutil
import subprocess
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError


def get_local_system_info():
    """Get comprehensive local system information including all network interfaces"""
    system_info = {
        'username': os.getlogin(),
        'hostname': socket.gethostname(),
        'interfaces': {}
    }

    # Get all network interfaces
    addresses = psutil.net_if_addrs()
    for interface, addr_list in addresses.items():
        for addr in addr_list:
            if addr.family == socket.AF_INET:  # IPv4 addresses only
                system_info['interfaces'][interface] = {
                    'ip_address': addr.address,
                    'netmask': addr.netmask,
                    'broadcast': getattr(addr, 'broadcast', None)
                }

    # Get primary IP (hostname resolution method)
    try:
        system_info['primary_ip'] = socket.gethostbyname(socket.gethostname())
    except socket.gaierror:
        system_info['primary_ip'] = "Could not determine primary IP"

    return system_info


def get_rdp_sessions():
    """Get detailed information about active RDP sessions using netstat and quser"""
    rdp_sessions = []

    try:
        # Get RDP connections from netstat
        netstat_cmd = 'netstat -n | findstr :3389 | findstr ESTABLISHED'
        netstat_output = subprocess.check_output(netstat_cmd, shell=True).decode('utf-8')

        # Parse remote IPs from netstat output
        remote_ips = []
        for line in netstat_output.splitlines():
            parts = line.strip().split()
            if len(parts) >= 2:
                # Get the remote address (format: IP:PORT)
                remote_address = parts[2]
                remote_ip = remote_address.split(':')[0]
                remote_ips.append(remote_ip)

        # Get user sessions from quser
        quser_output = subprocess.check_output('quser', shell=True).decode('utf-8')

        # Parse quser output to get active sessions
        for line in quser_output.splitlines()[1:]:  # Skip header
            parts = line.strip().split()
            username = parts[0]

            # Handle both active and disconnected states
            state = 'Active' if 'Active' in line else 'Disconnected'

            # Only include active sessions
            if state == 'Active':
                session_info = {
                    'username': username,
                    'state': state
                }

                # Try to match with a remote IP if available
                if remote_ips:
                    session_info['remote_ip'] = remote_ips.pop(0)
                else:
                    session_info['remote_ip'] = 'No IP detected'

                rdp_sessions.append(session_info)

    except subprocess.CalledProcessError as e:
        error_msg = str(e)
        if 'quser' in str(e):
            return []  # No sessions if quser fails
        return [{'error': f"Failed to get RDP sessions: {error_msg}"}]
    except Exception as e:
        return [{'error': f"Failed to get RDP sessions: {str(e)}"}]

    return rdp_sessions


def send_slack_message(client, channel, system_info, rdp_sessions):
    """Send system information using Slack SDK"""
    try:
        # Create the blocks for the message
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "🖥️ System Monitor Report",
                    "emoji": True
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Local System Information*\n"
                                f"• Hostname: {system_info['hostname']}\n"
                                f"• Username: {system_info['username']}\n"
                                f"• Primary IP: {system_info['primary_ip']}"
                    }
                ]
            },
            {
                "type": "divider"
            }
        ]

        # Add network interfaces
        interface_text = "*Network Interfaces*\n"
        for interface, details in system_info['interfaces'].items():
            interface_text += f"• {interface}: {details['ip_address']}\n"

        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": interface_text
            }
        })

        # Add RDP sessions
        blocks.append({"type": "divider"})
        if rdp_sessions:
            rdp_text = "*Active RDP Sessions*\n"
            for session in rdp_sessions:
                if 'error' in session:
                    rdp_text += f"Error: {session['error']}\n"
                    continue

                rdp_text += (f"• Username: {session['username']}\n"
                             f"  Remote Client IP: {session['remote_ip']}\n"
                             f"  State: {session['state']}\n\n")
        else:
            rdp_text = "*No active RDP sessions detected*"

        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": rdp_text
            }
        })

        # Send the message
        response = client.chat_postMessage(
            channel=channel,
            blocks=blocks,
            text="System Monitor Report"  # Fallback text
        )

        return response["ok"]
    except SlackApiError as e:
        print(f"Error sending message: {e.response['error']}")
        return False


def main():
    # Your Slack configuration
    SLACK_BOT_TOKEN = "xoxb-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
    SLACK_CHANNEL = "C080RQL464D"  # The channel to send messages to

    # Initialize Slack client
    client = WebClient(token=SLACK_BOT_TOKEN)

    # Get local system information
    print("\n=== Local System Information ===")
    local_info = get_local_system_info()
    print(f"Username: {local_info['username']}")
    print(f"Hostname: {local_info['hostname']}")
    print(f"Primary IP: {local_info['primary_ip']}")

    print("\n=== Network Interfaces ===")
    for interface, details in local_info['interfaces'].items():
        print(f"\nInterface: {interface}")
        print(f"IP Address: {details['ip_address']}")
        print(f"Netmask: {details['netmask']}")
        if details['broadcast']:
            print(f"Broadcast: {details['broadcast']}")

    # Get RDP session information
    print("\n=== Active RDP Sessions ===")
    rdp_sessions = get_rdp_sessions()

    if not rdp_sessions:
        print("No active RDP sessions found")
    else:
        for session in rdp_sessions:
            if 'error' in session:
                print(f"Error: {session['error']}")
                continue

            print(f"\nUsername: {session['username']}")
            print(f"Remote Client IP: {session['remote_ip']}")
            print(f"State: {session['state']}")

    # Send to Slack
    if send_slack_message(client, SLACK_CHANNEL, local_info, rdp_sessions):
        print("\nSuccessfully sent information to Slack")
    else:
        print("\nFailed to send information to Slack")


if __name__ == "__main__":
    main()
