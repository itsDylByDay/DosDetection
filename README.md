# IDS Tool: Real-Time DoS Detection Lab

## Objective

Developed a Python-based tool, to monitor network traffic to specifically detect potential Denial-of-Service (DoS) attacks in real-time on a local machine. This project simulates SOC Analyst responsibilities, such as threat detection and alerting.

### Skills Learned
- Gained proficiency in network traffic analysis using Scapy for packet sniffing.
- Stregnthed use of commands within Kali Linux
- Self-Introduction to a robust new Python Libraries.
- Developed real-time threat detection and alerting skills with Python and Tkinter.
- Enhanced understanding of DoS attack patterns and mitigation strategies.
  
### Tools Used
- Python scripting and logic implementation.
- Scapy for capturing and analyzing network packets.
- Tkinter for creating user-friendly pop-up alerts..


## Steps

*Ref 1: Local IP Detection*

![image](https://github.com/user-attachments/assets/30bdf8fd-f746-4b65-a2bb-0bbe5579d969)

*Description*: Verify that both virtual machines are on the same network, pinging via Kali Linux.

*Ref 2: Identify Target IP*

![image](https://github.com/user-attachments/assets/0e2e1cbc-27b7-4658-9e89-82b325327f3e)

*Description*: Displays "Network Detector" showing us that our IP address has been captured.

*Ref 3: Run Wireshark*

![image](https://github.com/user-attachments/assets/91378f34-ed09-47fa-884f-d899c476eeeb)

*Description*: Launch Wireshark as a means to analyze additional Network Traffic.
Add Specification to monitory target IP.

*Ref 4: Begin "Flood" on Target VM*

![image](https://github.com/user-attachments/assets/6b0da9ba-d70d-4859-9a6a-b469691ac4c3)

*Description*: Run 'hping3' command to simulate DoS attack.

*Ref 5: Network Alert upon DoS Attack*

![image](https://github.com/user-attachments/assets/08e37c67-55d4-47c4-9338-da615e199cd9)

*Description*: Displays the event that triggered a Network alert, as well as updated Wireshark log.

*Ref 6: Wireshark Analysis*

![image](https://github.com/user-attachments/assets/b00295d9-f73b-4acd-ae47-804b84db503f)

*Description*: Refer to the traffic logged on Wireshark to verify the Attack and its Origin. Overflow of failed SYN requests.

---
