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

    outfile = r"{0}\{1}_output".format(os.path.dirname(hash_file), os.path.basename(hash_file))
    cache = {}

    with open(hash_file, "r") as fa, open(outfile, "a") as out:
        for line in fa:
            myline = line.strip().split(",")
            file_path = myline[0]
            file_sha1 = myline[-1]

            #time.sleep(1)
            try:
                if file_sha1 not in cache:
                    params = {"apikey" : mykey, "resource" : "{0}".format(file_sha1)}
                    response = requests.get("https://www.virustotal.com/vtapi/v2/file/report", params=params)
                    if response.status_code == 200:
                        json_response = response.json()

                        if json_response["response_code"]:
                            print "{0},{1},{2},{3}/{4}\n".format(file_path, file_sha1, json_response["scan_date"], json_response["positives"], json_response["total"])
                            out.write("{0},{1},{2},{3}/{4}\n".format(file_path, file_sha1, json_response["scan_date"], json_response["positives"], json_response["total"]))
                            cache[file_sha1] = json_response
                        else:
                            print "{0},{1},NONE,NONE\n".format(file_path, file_sha1)
                            out.write("{0},{1},NONE,NONE\n".format(file_path, file_sha1))
                    else:
                        print "Request HTTP code: {0}".format(response.status_code)
                        pass
                else:
                    print "{0},{1},{2}/{3}\n".format(file_path, file_sha1, cache[file_sha1]["positives"], cache[file_sha1]["total"])
                    out.write("{0},{1},{2}/{3}\n".format(file_path, file_sha1, cache[file_sha1]["positives"], cache[file_sha1]["total"]))
            except Exception as e:
                print e
                pass

    outjson = r"{0}\{1}_json".format(os.path.dirname(hash_file), os.path.basename(hash_file))
    with open(outjson, "w") as oj:
        json.dump(cache, oj)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "\nUsage:\n\tpython vt-shiz.py [path to text file of hashes]\n"
        sys.exit()
    main()