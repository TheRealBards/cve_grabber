# cveGrabber

This is a quick and simple script that pulls the NVD Vulnerability list from https://nvd.nist.gov/vuln/data-feeds.

It's pretty messy, but gets the job done.

## Usage
```
git clone https://github.com/TheRealBards/cve_grabber.git
pip install -r cve_grabber/requirements.txt
mysql -u <user> -p <password> < cve_grabber/database/database_creator.sql
nohup python cve_grabber/cve_grabber.py &
```

##  Install Requirements
```
sudo apt-get install python-dev
sudo apt-get install libmysqlclient-dev
pip install -r requirements.txt
```

##  Required changes.

For the configuration file in config/config.yaml, you need to do the following:
- Enter the database details
- Enter the vendors that you're interested in

N.B.
It is recommended you change the file permissions of the config file. Something like `chmod 400 config/config.yaml`

## TODO
- Generate alerting/reporting for the vulnerabilities in Slack.      -- COMPLETE --
- Generate alerting/reporting for the vulnerabilities in MS Teams
- Suggestions?
