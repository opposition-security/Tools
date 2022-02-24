#!/usr/bin/python3

######################################################
# Author: Vosec                                      #
# Description: Removes all domain entries from       #
# every users safe senders. Export CSV from PPS      #
# Users menu then use import from file after script. #
######################################################

import csv
import re

# set variables
untrustedDomains = ["gmail.com", "outlook.com", "yahoo.com", "msn.com", "aol.com", "me.com", "icloud.com"]

# open new csv file for output
newuserlist = open('newuserlist.csv', 'w')

# build regex
domainRegex = ""
for domain in untrustedDomains:
    if domainRegex == "":
        domainRegex += "@" + domain
    else:
        domainRegex += "|@" + domain

# open input file obtained from PPS
with open('userlist.csv', newline='') as csvfile:
    # read csv into dictionary
    reader = csv.DictReader(csvfile)

    # create csv writer
    writer = csv.DictWriter(newuserlist, fieldnames=reader.fieldnames)
    # write out csv header to file
    writer.writeheader()

    # initialize counter
    removedEntries = 0

    # parse each row in userlist csv
    for row in reader:
        # skip if the user doesn't have any safe sender entries
        if row['safelist'] != "":
            # create list of safe sender entries for user
            safelist = row['safelist'].split(";")
            # create blank list for email addresses
            newsafelist = []

            # iterate through each entry
            for entry in safelist:
                untrustedDomain = re.search(domainRegex, entry)
                # check if the entry is an email or domain
                if ("@" in entry) and not untrustedDomain and not (entry.startswith('@')):
                    # if entry is not an untrusted email, add to list for export
                    newsafelist.append(entry)
                else:
                    removedEntries += 1
                    print(entry)

            # convert list to semicolon separated string
            newcsvsafelist = ';'.join(newsafelist)
            # write the filtered safe senders back to the csv row
            row['safelist'] = newcsvsafelist

        # write the row to the output file
        writer.writerow(row)

# close output file
newuserlist.close()

# print count of entries removed
print("Removed " + str(removedEntries) + " Entries")
