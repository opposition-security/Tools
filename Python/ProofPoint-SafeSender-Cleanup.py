#!/usr/bin/python3

######################################################
# Author: Vosec                                      #
# Description: Removes all domain entries from       #
# every users safe senders. Export CSV from PPS      #
# Users menu then use import from file after script. #
######################################################

import csv

# open new csv file for output
newuserlist = open('newuserlist.csv', 'w')

# open input file obtained from PPS
with open('userlist.csv', newline='') as csvfile:
    # read csv into dictionary
    reader = csv.DictReader(csvfile)

    # create csv writer
    writer = csv.DictWriter(newuserlist, fieldnames=reader.fieldnames)
    # write out csv header to file
    writer.writeheader()

    # parse each row in userlist csv
    for row in reader:
        # skip if the user doesn't have any safe sender entries
        if row['whitelist'] != "":
            # create list of safe sender entries for user
            safelist = row['whitelist'].split(";")
            # create blank list for email addresses
            newsafelist = []

            # iterate through each entry
            for entry in safelist:
                # check if the entry is an email or domain
                if "@" in entry:
                    # if entry is an email, add to list for export
                    newsafelist.append(entry)
                    
            # convert list to semicolon separated string
            newcsvsafelist = ';'.join(newsafelist)
            # write the filtered safe senders back to the csv row
            row['whitelist'] = newcsvsafelist

        # write the row to the output file    
        writer.writerow(row)

# close output file
newuserlist.close()
