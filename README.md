# ADOffline

## Summary

Most penetration testers, or those engaged in simulated attacks or red team activities, will understand the value of reconnisance. On large corporate networks, this will involve a fair amount of Active Directory querying. There are some exceptionally powerful tools built into Empire, PowerTools and Metasploit, but these all rely on an active connection to a domain controller.

This tool combines the flexibility of SQL with the raw detail in Active Directory by parsing the raw LDAP output from Active Directory into a SQLite database. This can then be used to explore user and group membership and download all computer information.

There is a huge amount of information stored in LDAP; this tool does not seek to recover it all, but instead should help with planning attacks or identifying high value target users without needing to constantly query AD.

It is work in progress; all commits/PRs/support welcome. 

_AT THE MOMENT, THIS IS ALPHA CODE_. It has not been fully tested and is not production ready.

## Benefits

* Allows enumeration of users, computers (including hostname, OS etc) and groups; these are all derived from users.
* Parses flags (e.g. sAMAccountType, userAccountControl) for intuitive searching.
* Easy to enumerate basic and nested group membership.

## Drawbacks

* Will take a while to parse a large LDIF file. During testing, it took 30 minutes to parse a large domain containing roughly 100,000 users, groups and computers.
* Reqires a large data exchange with the domain controller which may be noticed. For example, the domain above generated a 400Mb LDAP file, although this was generated in approximately 4 minutes.
* Does not currently consider foreign groups (i.e. from trusts).

## Usage

This assumes that you have low privilege (e.g. standard user) access to a domain and that you are able to connect to TCP/389 (LDAP) on a domain controller. On an internal penetration test, you can access a domain controller directly but, on a simulated attack or red team, use a port forward or SOCKS proxy or equivalent.

1. Use ldapsearch to download the Active Directory structure. At the current time of writing, the script only parses the 'user' object class; this will have the effect of parsing all users, groups and computers on the domain.
2. ldapsearch will generate an LDIF file which is an ASCII text file containing the AD structure. Import this into a SQLite database using adoffline.py.
3. Query the SQLite database using a command line tool or a front end.

## Efficiency

The current version is not complete; there are several efficiency improvements to be made and features to be added. It currently:

* Stores users, groups and computers
* Calculates nested groups for users only

This was tested on a real client domain with approximately 100,000 individual users, groups and computers. It took approximately 30 minutes to parse the original LDIF file and generate the database and another half an hour to work out the nested groups on a laptop (single threaded).

```
$ ldapsearch -h <ip> -x -D <username> -w <password> -b <base DN> -E pr=1000/noprompt -o ldif-wrap=no > client.ldif
...

$ ls -lah client.ldif
-rw-r--r--  1 stuart  users   391M Jan 21 08:18 client.ldif

$ python adoffline.py client.ldif
AD LDAP to SQLite Offline Parser
Stuart Morgan (@ukstufus) <stuart.morgan@mwrinfosecurity.com>

[31/Jan/16 23:31:52] Creating database: /tmp/tmpBQXkFH.20160131233152.ad-ldap.db
[31/Jan/16 23:31:52] Reading LDIF...done
[31/Jan/16 23:31:53] Parsing LDIF...
  Reading line 7001808/7001808 (100%)
[31/Jan/16 23:59:24] Calculating chain of ancestry (nested groups)...
  Processed user 27385/27385 (100%)
[01/Feb/16 00:27:35] Completed

        Users: 27385
       Groups: 38334
    Computers: 29142
 Associations: 2102885
 
$ ls -lah /tmp/tmpBQXkFH.20160131233152.ad-ldap.db
-rw-r--r--  1 stuart  wheel   1.0G Feb  1 00:27 /tmp/tmpBQXkFH.20160131233152.ad-ldap.db
```

The database size for the above example was 1GB which is perfectly manageable.

## Database Structure

## Examples
