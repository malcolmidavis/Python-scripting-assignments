#Script: Cyber Investigation Toolkit
#Purpose: Analyze a directory for keywords and IOCs, extract information, and archive reports

#Import Python Standard Libraries
from pathlib import Path
import re
import zipfile

#Import Third-Party Libraries
from prettytable import PrettyTable

#Temporary variables that you will delete when you make them in your code
#These are here because they exist in some of the provided code and will cause errors if not declared

#Regular Expression Patterns
email_pattern = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
url_pattern = re.compile(r"https?://[^\s]+")
ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
word_pattern = re.compile(r"[a-zA-Z][a-zA-Z0-9_-]{2,}")

#Create empty lists to store the results of the regular expression searches
email_list = []
url_list = []
ip_list = []
word_list = []

#Display the current working directory to the user
cwd = Path.cwd()
print(f"Current Working Directory: {cwd}")

#Create the keywords list
keyword_path = Path("CyberInvestigation") / "Indicators" / "keywords.txt"

with open(keyword_path, "r") as file:
    keywords = file.read()

keywords_list = keywords.split()

#Display the keyword list to the user
print("\nKeywords to be used in the analysis include:")

for number, keyword in enumerate(keywords_list, start=1):
    print(f"{number}: {keyword}")

#Prompt the user to enter chunk_size and validate the input to match the requirements
while True:
    try:
        chunk_size = int(input("\nEnter a chunk size in bytes between 64 and 65536: "))

        if chunk_size < 64:
            print("\nChunk size must be greater than or equal to 64")
        elif chunk_size > 65536:
            print("\nChunk size must be less than or equal to 65536")
        else:
            print(f"Chunk size set to {chunk_size}")
            break

    except ValueError:
        print("You have typed an invalid value. The chunk size must be between 64 and 65536 ")

#Display the directories in the current working directory
print(f"\nDirectories in {cwd.name}")

for item in cwd.iterdir():
    if item.is_dir():
        print(f"\nDirectory {item.name}")

#Ask the user to enter in the investigation directory
#Validate the directory exits and is a directory
while True:
    try:
        directory_name = input("\nEnter a directory name to be scanned: ")

        investigation_directory = Path(directory_name)

        if not investigation_directory.exists():
            raise FileNotFoundError(f"{directory_name} was not found")

        elif not investigation_directory.is_dir():

            raise NotADirectoryError(f"{directory_name} is not a directory.")
        else:
            print(f"\nThe directory {investigation_directory} will be scanned.")
            break

    except FileNotFoundError as e:
        print(f"File Error: {e}")
    except NotADirectoryError as e:
        print(f"Directory Error: {e}")
    except Exception as e:
        print(f"Unexpected Error: {e}")

#Begin the Investigation Processing Section
try:
    #Gather all the .txt, .log, and .csv files recursively
    files_to_process = []

    for extension in ["*.txt", "*.log", "*.csv"]:
        files_to_process.extend(investigation_directory.rglob(extension))

    files_to_process = sorted(files_to_process)

    #Verify that files were found
    if len (files_to_process) == 0:
        raise FileNotFoundError(f"No .txt, .log, or .csv files found in {investigation_directory.name}")

    #Create, populate, and display a PrettyTable with the information related to the files that were found.
    file_table = PrettyTable()
    file_table.field_names = ["File Name", "Extension", "Relative Path", "Size in Bytes"]
    file_table.title = f"{len(files_to_process)} Files Located for Processing"
    file_table.align = "l"

    for file_path in files_to_process:
        file_table.add_row([
            file_path.name,
            file_path.suffix,
            file_path.relative_to(investigation_directory),
            file_path.stat().st_size
        ])

    print(file_table.get_string(sortby="Size in Bytes", reversesort=True))

    #Search for keywords in the files
    keyword_hits = {}
    for keyword in keywords_list:
        keyword_hits[keyword] = 0

    #Declare 2 counter variables and print a heading
    chunks_processed = 0
    files_processed = 0

    print("\nSearching file for keywords and artifacts")

    #Looping through the files_to_process by the chunk_size
    for file_path in files_to_process:
        with open(file_path, "rb") as file:
            files_processed += 1

            while True:
                file_chunk = file.read(chunk_size)

                if not file_chunk:
                    break

                chunks_processed += 1
                file_chunk = file_chunk.lower()

                #Search for each keyword
                file_chunk = file_chunk.lower()

                for keyword in keywords_list:
                    if keyword.encode() in file_chunk:
                        keyword_hits[keyword] += 1

                #Capturing results from the regular expressions patterns
                file_chunk = file_chunk.decode("utf-8", errors="ignore")

                for email in re.findall(email_pattern, file_chunk):
                    email_list.append(email)

                for url in re.findall(url_pattern, file_chunk):
                    url_list.append(url)

                for ip in re.findall(ip_pattern, file_chunk):
                    ip_list.append(ip)

                for word in re.findall(word_pattern, file_chunk):
                    word_list.append(word)

    #Create, populate, and display the key_word Pretty Table
    keyword_table = PrettyTable()
    keyword_table.field_names = ["Keyword", "Occurrences"]
    keyword_table.title = "Keyword Search Results"
    keyword_table.align = "l"

    for keyword, count in keyword_hits.items():
        keyword_table.add_row([keyword, count])

    print(keyword_table.get_string(sortby="Keyword"))

    #Create, populate, and display the artifact_table Pretty Table
    artifact_table = PrettyTable()
    artifact_table.field_names = ["Artifact", "Occurrences"]
    artifact_table.title = "Artifact Search Results"
    artifact_table.align = "l"

    artifact_table.add_row(["Email Addresses", len(email_list)])
    artifact_table.add_row(["URLs", len(url_list)])
    artifact_table.add_row(["IPs", len(ip_list)])
    artifact_table.add_row(["Words", len(word_list)])

    print(artifact_table)

    #Display the first 10 email addresses
    print("\nFirst 10 Email Addresses:")
    for email in email_list[:10]:
        print(email)

    print("\nFirst 10 URLs:")
    for url in url_list[:10]:
        print(url)

    print("\nFirst 10 IPs:")
    for ip in ip_list[:10]:
        print(ip)

    print("\nFirst 10 Words:")
    for word in word_list[:10]:
        print(word)

    #Create the file names for each of the reports
    files_report = Path("Davis_File_Processed_Report.txt")
    keyword_report = Path("Davis_Keyword_Report.txt")
    artifact_report = Path("Davis_Artifact_Report.txt")
    email_report = Path("Davis_Email_Report.txt")
    url_report = Path("Davis_URL_Report.txt")
    ip_report = Path("Davis_IP_Report.txt")
    word_report = Path("Davis_Word_Report.txt")
    zip_file = Path("Davis_Results.zip")

    #Add the filenames to a list to make it easier to loop through when you zip them
    report_list = [files_report, keyword_report, artifact_report, email_report,
                   url_report, ip_report, word_report]

    #Create a heading that will be at the top of each report
    report_heading = "\nCyber Investigation Report by Malcolm Davis\n"
    report_heading += "=" * 50
    report_heading += f"\nInvestigation Directory: {investigation_directory.name}"
    report_heading += f"\nFiles Processed: {files_processed}"
    report_heading += f"\nChunks Processed: {chunks_processed}\n\n"

    #Writing the content to each of the reports
    print("\nCreating report files...")
    with open(files_report, "w") as file:
        file.write(report_heading)
        file.write(file_table.get_string(sortby="Size in Bytes", reversesort=True))
    print(f"{files_report}created.")

    with open(keyword_report, "w") as file:
        file.write(report_heading)
        file.write(keyword_table.get_string(sortby="Keyword"))
    print(f"{keyword_report}created.")

    with open(artifact_report, "w") as file:
        file.write(report_heading)
        file.write(str(artifact_table))
    print(f"{artifact_report}created.")

    with open(email_report, "w") as file:
        file.write(report_heading)
        for email in email_list:
            file.write(email + "\n")
    print(f"{email_report}created.")

    with open(url_report, "w") as file:
        file.write(report_heading)
        for url in url_list:
            file.write(url + "\n")
    print(f"{url_report}created.")

    with open(ip_report, "w") as file:
        file.write(report_heading)
        for ip in ip_list:
            file.write(ip + "\n")
    print(f"{ip_report}created.")

    with open(word_report, "w") as file:
        file.write(report_heading)
        for word in sorted(set(word_list)):
            file.write(word + "\n")
    print(f"{word_report}created.")

    #Create a ZIP Archive of all the reports
    with zipfile.ZipFile(zip_file, "w") as archive:
        for file in report_list:
            archive.write(file, arcname=file.name)

    print(f"\nZip archive created: {zip_file}")

except FileNotFoundError as e:
    print(f"\nFile Error: {e}")
except NotADirectoryError as e:
    print(f"\nDirectory Error: {e}")
except Exception as e:
    print(f"\nUnexpected Error: {e}")





