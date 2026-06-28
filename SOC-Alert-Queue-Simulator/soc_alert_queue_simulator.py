#Script: SOC Alert Queue Simulator
#Purpose: Simulate SOC alert management by generating, categorizing, and summarizing security alerts based on severity.

#Import Standard Python Libraries
import random

#Variable and List Declarations
alert_types = ["Malware", "Phishing", "Unauthorized Access",
               "Credential Theft", "Port Scan",
               "Brute Force Attempt", "Suspicious Login",
               "Privilege Escalation", "Data Exfiltration",
               "Ransomware"]

alert_queue = []
low_alerts = []
medium_alerts = []
high_alerts = []
critical_alerts = []

analyst_name = "Malcolm Davis"


print(f" Junior SOC Analyst Simulator by {analyst_name} ".center(80, "*"))
print()

#Populate the alert_queue list with 50 random alerts from alert_types
for alert in range(50):
    random_alert = random.choice(alert_types)
    alert_queue.append(random_alert)

#Display the original alert_queue using a for loop and enumerate
print(f" Original Alert Queue ".center(80, "-"))
for number, alert in enumerate(alert_queue, start=1):
    print(f"{number}. {alert}")

#Updating the alert_queue list
alert_queue.append("Insider Threat")

alert_queue.insert(4, "Remote Access")

if "Malware" in alert_queue:
    alert_queue.remove("Malware")

if "Phishing" in alert_queue:
    phishing_index = alert_queue.index("Phishing")
    del alert_queue[phishing_index]

alert_queue.sort(reverse=True)

#Display the Updated alert_queue using a for loop and enumerate
print()
print(f" Updated Alert Queue ".center(80, "-"))

for number, alert in enumerate(alert_queue, start=1):
    print(f"{number}. {alert}")

#Processing the Alerts
for alert in alert_queue:
    if alert == "Ransomware" or alert == "Data Exfiltration":
        critical_alerts.append(alert)
    elif (alert == "Privilege Escalation" or alert == "Credential Theft"
          or alert == "Insider Threat"):
        high_alerts.append(alert)
    elif(alert == "Phishing" or alert == "Brute Force Attempt"
        or alert == "Malware" or alert == "Unauthorized Access"):
        medium_alerts.append(alert)
    else:
        low_alerts.append(alert)


#Displaying the Summary of the alert_queue
print()
print(f" Alert Queue SOC Summary ".center(80, "-"))

print()
print(f"The following {len(critical_alerts)} alerts were detected:")
for alert in critical_alerts:
    print(f"\t*{alert}")

print()
print(f"The following {len(high_alerts)} alerts were detected:")
for alert in critical_alerts:
    print(f"\t*{alert}")

print()
print(f"The following {len(medium_alerts)} alerts were detected:")
for alert in critical_alerts:
    print(f"\t*{alert}")

print()
print(f"The following {len(low_alerts)} alerts were detected:")
for alert in critical_alerts:
    print(f"\t*{alert}")

#Determine how many times Ransomware and Data Exfiltration appear in the critical_alerts
ransomware_count = 0
data_exfiltration_count = 0

for alert in critical_alerts:
    if alert == "Ransomware":
        ransomware_count += 1
    elif alert == "Data Exfiltration":
        data_exfiltration_count += 1

#Display the findings of the number of times Ransomware and Data Exfiltration appear
print()
print("Critical Alert Findings")
print(f"\tRansomware: {ransomware_count}")
print(f"\tData Exfiltration: {data_exfiltration_count}")








