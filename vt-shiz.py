# initial purpose of this script is to accept a csv file of file path - hashes and query those in VT

import requests
import json
import os, sys
import time


conf = "config.json"
cache = []

fo = open(conf, "r")
conf_json = json.loads(fo.read())
fo.close()


def main():
    mykey = conf_json["apikey"]
    hash_file = sys.argv[1]
    if not os.path.exists(hash_file):
        print "The text file you provided does not exists!"
        sys.exit()

    with open(hash_file, "r") as fa:
        for line in fa:
            myline = line.strip().split(",")
            file_path = myline[0]
            file_sha1 = myline[-1]
            print file_path, file_sha1

            time.sleep(15)

            params = {"apikey" : mykey, "resource" : "{0}".format(file_sha1)}
            response = requests.get("https://www.virustotal.com/vtapi/v2/file/report", params=params)
            json_response = response.json()
            print json_response
            break


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "\nUsage:\n\tpython vt-shiz.py [path to text file of hashes]\n"
        sys.exit()
    main()