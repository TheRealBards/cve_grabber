#!/usr/bin/env python

__author__ = "Bardia Omran"
__version__ = "1.0.1"
__twitter__ = "@TheRealBards"
__status__ = "Stable"

## Imports ##
import os
import sys
import time
import json
import logging
import StringIO
from datetime import datetime

try:
    import requests # pip install requests
except Exception as e:
    sys.exit(e)

try:
    import zipfile
except Exception as e:
    sys.exit(e)

try:
    import yaml # pip install pyyaml
except Exception as e:
    sys.exit(e)

try:
    import MySQLdb # pip install mysqlclient
except Exception as e:
    sys.exit(e)

try:
	from prettytable import PrettyTable # pip install prettytable
except Exception as e:
	sys.exit(e)

try:
	from slackclient import SlackClient
except Exception as e:
	sys.exit(e)

##
# 	TODO:
# 		1. Generate weekly report		 						   	- COMPLETE -
#  		2. Add Slack details to config.yaml								- COMPLETE -
#  		3. Add weekly report to Slack									- COMPLETE -
# 		4. Depending on number of results, messages are truncated in Slack, breaking the table.		- COMPLETE -
# 			* Split the table in more manageable sizes.						- COMPLETE -
##

## Logging ##
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
stdouthandler = logging.StreamHandler(sys.stdout)
stdouthandler.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
stdouthandler.setFormatter(formatter)
logger.addHandler(stdouthandler)

## Variables and Settings ##
BASE_DIR = os.getcwd()
logger.debug(BASE_DIR)
URL = "https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2018.json.zip"
todays_date = datetime.today().strftime("%Y-%m-%d") # ISO-8601 date format

## Load YAML configuration file ##
if os.path.isfile(BASE_DIR + "/config/config.yaml"):
	try:
		with open(BASE_DIR + "/config/config.yaml") as yamlConfig:
			config = yaml.load(yamlConfig)
	except Exception as e:
		logger.error(e)
else:
	logger.warn("YAML configuration file doesn't exist...")
	logger.info("YAML file loaded")

## Database settings ##
try:
        db = MySQLdb.connect(config['database']['host'],config['database']['user'], config['database']['password'], config['database']['database_name'])
        cursor = db.cursor()
except Exception as e:
        logger.error(e)

def weekly_report():
	SQL = "SELECT cve, vendor, product, cve_published_date, cve_last_modified_date, date_added_to_db FROM cve WHERE (cve_published_date BETWEEN NOW() - INTERVAL DAYOFWEEK(NOW())+6 DAY AND NOW() - INTERVAL DAYOFWEEK(NOW())-1 DAY) OR (cve_last_modified_date BETWEEN NOW() - INTERVAL DAYOFWEEK(NOW())+6 DAY AND NOW() - INTERVAL DAYOFWEEK(NOW())-1 DAY)"
	logger.debug(SQL)
	try:
		logger.info("Generating Weekly Report")
		cursor.execute(SQL)
	except Excetion as e:
		logger.error(e)
		return 1
	results = cursor.fetchall()
	table = PrettyTable(["cve", "vendor", "product", "cve_published_date", "cve_last_modified_date", "date_added_to_db"])
	if config['slack']['enabled'].lower() == "true":
		notify("~~ *Weekly CVE Report* ~~")
		chunks = [results[x:x+10] for x in xrange(0, len(results), 10)]
		for each_chunk in chunks:
			for x in each_chunk:
				cve = x[0]
				vendor = x[1]
				product = x[2]
				cve_published_date = str(x[3])
				cve_last_modified_date = str(x[4])
				date_added_to_db = str(x[5])
				table.add_row([cve, vendor, product, cve_published_date, cve_last_modified_date, date_added_to_db])
			notify('```\n' + str(table) + '\n```')
			table.clear_rows()
	else:
		for x in results:
			cve = x[0]
			vendor = x[1]
			product = x[2]
			cve_published_date = str(x[3])
			cve_last_modified_date = str(x[4])
			date_added_to_db = str(x[5])
			table.add_row([cve, vendor, product, cve_published_date, cve_last_modified_date, date_added_to_db])
		return str(table)

def notify(message):
	API_KEY = "Bearer " + config['slack']['api_key']
	headers = {
		'Authorization': API_KEY,
		'Content-type': 'application/json'
	}
	data = {
		"channel": config['slack']['to'][0],
		"text": message
	}
	response = requests.post('https://slack.com/api/chat.postMessage', headers=headers, data=str(data))
	return response.content

def check_exists(cve):
        logger.info("Checking if CVE: "+cve+" exists.")
        SQL = "SELECT cve FROM cve WHERE cve = '{}'"
        SQL = SQL.format(cve)
        if cursor.execute(SQL):
                logger.info("CVE: "+cve+" does exist")
                return True
        else:
                logger.info("CVE: "+cve+" doesn't exist")
                return False

def main():
        ## Load YAML configuration file ##
        if os.path.isfile(BASE_DIR + "/config/config.yaml"):
            try:
                with open(BASE_DIR + "/config/config.yaml") as yamlConfig:
                    config = yaml.load(yamlConfig)
            except Exception as e:
                logger.error(e)
        else:
            logger.warn("YAML configuration file doesn't exist...")
        logger.info("YAML file reloaded...")
        res = []
        CVE = requests.get(URL, stream=True)

        if CVE.status_code == 200:
                zipExtract = zipfile.ZipFile(StringIO.StringIO(CVE.content))
                zipExtract.extractall(BASE_DIR + '/cve_data/')

                with open(BASE_DIR + '/cve_data/nvdcve-1.0-2018.json') as f: 
                        CVE = json.loads(f.read())

                count_comitted = 0

                for x in CVE["CVE_Items"]:
                        SQL = 'INSERT INTO cve (cve, vendor, product, version, description, reference, cve_published_date, cve_last_modified_date, date_added_to_db) VALUES ("{}", "{}", "{}", "{}", "{}", "{}", "{}", "{}", "{}")'
                        if x["cve"]["affects"]["vendor"]["vendor_data"]:
                                vendor = x["cve"]["affects"]["vendor"]["vendor_data"][0]["vendor_name"]
                                if vendor.lower() in config['vendors']: # We're interested
                                        description = x["cve"]["description"]["description_data"][0]["value"]
                                        cve_date = datetime.strptime(x['publishedDate'],"%Y-%m-%dT%H:%MZ").strftime('%Y-%m-%d')
                                        last_modified_date = datetime.strptime(x['lastModifiedDate'],"%Y-%m-%dT%H:%MZ").strftime('%Y-%m-%d')
                                        cve = x["cve"]["CVE_data_meta"]["ID"]
                                        vendor = x["cve"]["affects"]["vendor"]["vendor_data"][0]["vendor_name"]
                                        product = x["cve"]["affects"]["vendor"]["vendor_data"][0]["product"]["product_data"][0]["product_name"]
                                        version = x["cve"]["affects"]["vendor"]["vendor_data"][0]["product"]["product_data"][0]["version"]["version_data"]
                                        version = [y["version_value"] for y in x["cve"]["affects"]["vendor"]["vendor_data"][0]["product"]["product_data"][0]["version"]["version_data"]]
                                        references = x["cve"]["references"]["reference_data"]
                                        references = [z["url"] for z in references]
                                        if check_exists(cve) == False:
                                                SQL = SQL.format(cve, vendor, product, MySQLdb.escape_string(str(version)), MySQLdb.escape_string(description), MySQLdb.escape_string(str(references)), cve_date, last_modified_date, todays_date)
                                                supress_1L = cursor.execute(SQL)
                                                #print SQL
                                                count_comitted += 1
                                        os.system("clear")
                                        logger.info("Checking CVE: "+str(cve))

                logger.info("Commiting "+str(count_comitted)+" records to the database.")
                db.commit()
                logger.info("Going to sleep for 10 minutes")
                time.sleep(600)
        else:
                logger.info("Going to sleep for 10 minutes")
                time.sleep(600)

if __name__ == '__main__':
        tick = 0
        while True:
                main()
                if tick == 0:
                        if datetime.today().weekday() == 0: # Monday
                                tick += 1
                                weekly_report()
                        elif datetime.today().weekday() == 6: # Sunday
                                tick = 0 # Refresh
