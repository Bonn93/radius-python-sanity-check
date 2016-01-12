This is a core set of scripts to verify a MS based Radius server is responding and to authentication/authorisation requests. MS Windows will report the service as running, however it could have many errors returned, and an actual authentication problem be present.

Core parts of this repo include;

check_radius.py - The core script. Expects params such as username,password,secret,host and custom port if required.
zabbix_executor.sh - A bash script to run under {$datadir/zabbix/externalscripts} as per your zabbix_server.conf
lvs_executor.sh - A bash script to execute under a RHEL/CentOS load balancer to check the backend raidus servers are alive and report into Nanny.
Auth/ - Source code from the reverse engineered Java MSCHAPv2 specification hacked into python.
Lib/ - Dictionary Construction folder with RFC links.

Will work with MSCHAPv2/PAP/CHAP. Untested, last working CentOS 5. Plans to update and test with CentOS 7. 
