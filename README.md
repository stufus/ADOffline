# ADOffline

## Summary

Most penetration testers, or those engaged in simulated attacks or red team activities, will understand the value of reconnisance. On large corporate networks, this will involve a fair amount of Active Directory querying. There are some exceptionally powerful tools built into Empire, PowerTools and Metasploit, but these all rely on an active connection to a domain controller.

This tool combines the flexibility of SQL with the raw detail in Active Directory by parsing the raw LDAP output from Active Directory into a SQLite database. This can then be used to explore user and group membership and download all computer information.

There is a huge amount of information stored in LDAP; this tool does not seek to recover it all, but instead should help with planning attacks or identifying high value target users without needing to constantly query AD.

It is work in progress; all commits/PRs/support welcome. 

## Benefits

* Allows enumeration of users, computers (including hostname, OS etc) and groups; these are all derived from users.
* Parses flags (e.g. sAMAccountType, userAccountControl) for intuitive searching.
* Easy to enumerate basic group membership.
** Automatic calculation of nested group membership will be added shortly.

## Drawbacks

* Will take a while to parse a large LDIF file. During testing, it took 20 minutes to parse a domain containing 30,000 users.
* Reqires a large data exchange with the domain controller which may be noticed. For example, the domain above generated a 400Mb LDAP file, although this was generated in approximately 4 minutes.

## Usage

This assumes that you have low privilege (e.g. standard user) access to a domain and that you are able to connect to TCP/389 (LDAP) on a domain controller. On an internal penetration test, you can access a domain controller directly but, on a simulated attack or red team, use a port forward or SOCKS proxy or equivalent.

1. Use ldapsearch to download the Active Directory structure. At the current time of writing, the script only parses the 'user' object class; this will have the effect of parsing all users, groups and computers on the domain.
2. ldapsearch will generate an LDIF file which is an ASCII text file containing the AD structure. Import this into a SQLite database using adoffline.py.
3. Query the SQLite database using a command line tool or a front end.

## Database Structure

## Examples
