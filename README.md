# Radius-Python-Sanity-Check

This is a core set of scripts to verify a MS based Radius server is responding and to authentication/authorisation requests. MS Windows will report the service as running, however it could have many errors returned, and an actual authentication problem be present.
### Version
1.0

### Tech

Lots of hacky stuff from Java, MS to get MSCHAPv2 objects / auth working

* [check_radius.py] - Core script called by the executors, relies on mschapv2.py and lib/ lib/dicts
* [mschapv2.py] - MSCHAPv2 Handler
* [zabbix_executor.sh] - Zabbix External Script
* [lvs_executor.sh] - RHEL LVS Script to feed into IPVSADM/LVS

### Installation

You need Python 2.7

```sh
$ coming soon
```

### Usage 
./check_radius.py --username 'your_username' --password 'said_users_password' --port 'your_radius_port' --host 'raidus_host_or_balancer' --secret 'your_radius_secret'

LVS and Zabbix shell scripts to run the above and input pre-configred details. 

### Credit and Notes
Credit to Lee Webb for the initial script and finding the Java Reverse Engineering sections for MSCHAP. 
