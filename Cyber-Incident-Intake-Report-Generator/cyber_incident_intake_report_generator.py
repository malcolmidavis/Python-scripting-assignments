#Script: Cyber Incident Intake Report Generator
#Purpose: Collect incident details, process user input, and generate a formatted cybersecurity incident report.

#Variable Declarations
organization_name = "university of arizona cyber operations center"
report_title = "cyber incident intake report"
default_status = "open"
tool_name = "python"
classification_level = "internal use only"
MAX_SEVERITY_SCORE = 10

print("Please provide the requested details")

analyst_first_name = input("Enter Analyst First Name: ")
analyst_last_name = input("Enter Analyst Last Name: ")
incident_id = input("Enter Incident ID: ")
hostname = input("Enter Hostname or Workstation Name: ")
suspicious_filename = input("Enter Suspicious Filename: ")
incident_description = input("Enter a short description of the event: ")

severity_score = int(input("Enter severity level from 1 to 10: "))
minutes_reviewed = float(input("Enter time in minutes spent reviewing: "))

analyst_full_name = f"{analyst_first_name} {analyst_last_name}".title()
formatted_incident_id = incident_id.upper()
formatted_hostname = hostname.lower()
clean_filename = suspicious_filename.strip()
formatted_filename = clean_filename.replace(" ", "_")
description_length = len(incident_description)
letter_a_count = incident_description.lower().count("a")
keyword_location = incident_description.lower().find("malware")

remaining_severity_points = MAX_SEVERITY_SCORE - severity_score
review_time_hours = minutes_reviewed / 60

print("\n" + "*" * 80)
print(report_title.title().center(80))
print("*" * 80)

print(f"Organization Name: {organization_name.title()}")
print(f"Report Status: {default_status.upper()}")
print(f"Classification Level: {classification_level.upper()}")

print(f"\nAnalyst Name: {analyst_full_name}")
print(f"Incident ID: {formatted_incident_id}")
print(f"Hostname or Workstation Name: {formatted_hostname}")
print(f"Suspicious Filename: {clean_filename}")
print(f"Formatted Filename: {formatted_filename}")

print(f"\nIncident Description:")
print(incident_description.strip())

print(f"\nDescription Length: {description_length}")
print(f"The letter 'a' appears {letter_a_count} times.")
print(f"The keyword 'malware' appears at index {keyword_location}.")

print(f"\nSeverity Score: {severity_score} out of {MAX_SEVERITY_SCORE}")
print(f"Remaining Severity Points: {remaining_severity_points}")
print(f"Review Time: {minutes_reviewed} minutes")
print(f"Review Time in Hours: {review_time_hours:.2f}")

print("\nZen of Python Reminder:")
print("Simple is better than complex.")
print("Readable and maintainable code helps cyber analysts avoid mistakes and understand reports quickly.")

print("*" * 80)
