# ADOffline

## Summary

Most penetration testers, or those engaged in simulated attacks or red team activities, will understand the value of reconnisance. On large corporate networks, this will involve a fair amount of Active Directory querying. There are some exceptionally powerful tools built into Empire, PowerTools and Metasploit, but these all rely on an active connection to a domain controller.

This tool combines the flexibility of SQL with the raw detail in Active Directory by parsing the raw LDAP output from Active Directory and inserting it into a SQLite database. This can then be used to explore user and group membership and download all computer information.

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

This was tested on a real client domain with approximately 100,000 individual users, groups and computers. It took approximately 30 minutes to parse the 7 million lines in the original LDIF file to generate the database and another half an hour to work out the nested groups on a laptop (single threaded).

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

A user, group and computer is, in essence, the same thing as far as LDAP is concerned. There are some attributes that do not make sense if you are not a computer (e.g. operatingSystem) but at a high level, each of these records is considered as a user at heart. However, there are a number of SQL views that can be used to offer easy identification of computers, groups and users in a more intuitive manner.

### LDAP Fields Captured

The table below shows the LDAP attributes that ADOffline currently identifies and parses. Note that in some cases, the description is based on the believed general usage of the attribute; there may be circumstances where an organisation uses this field for a different reason. 

The actual fields in the database are covered later; this is because the fields below are sometimes parsed and interpreted in order to make their meaning clearer. 

Attribute | Purpose
------------| -------
objectClass | The type of object.
title | The job title of an individual.
cn | The name that represents an object. This is usually the name of the user, computer or group.
givenName | Contains the given name (first name) of the user.
sn | Surname
description | This is a free-text field which is usually used to store comments relating to this user, computer or group. Sometimes it can have useful information such as default passwords, the purpose of the user or an explanation of how to interact with them. By default, Ben Campbell's metasploit POST module (post/windows/gather/enum_ad_user_comments) works by searching the description field for 'pass' although this is configurable.
instanceType | This is described by Microsoft as "A bitfield that dictates how the object is instantiated on a particular server. The value of this attribute can differ on different replicas even if the replicas are in sync.". Generally speaking, it seems to be 4.
displayName | Usually the full name of the user
member | Groups can have zero or more 'member' attributes; this indicates that the DN specified is a member of that group.
memberOf | Groups, users and computers can have zero or more 'memberOf' attributes; this indicates that the current DN is a member of the DN specified.
name | Seems to be the same as displayName most of the time
dNSHostName | For computers, it is the DNS hostname of the computer.
userAccountControl | Flags that control the behaviour of the user account. See https://msdn.microsoft.com/en-us/library/windows/desktop/ms680832%28v=vs.85%29.aspx for a description, but ADOffline parses them to make them easier to search for.
badPwdCount | The number of times the user tried to log on to the account using an incorrect password. A value of 0 indicates that the value is unknown. See https://technet.microsoft.com/en-us/library/cc775412%28WS.10%29.aspx for a description; it appears that this is maintained on a per-DC basis and is reset (on the specific DC) when there is a successful login. 
primaryGroupID | The PrimaryGroupID attribute on a user or group object holds the RID of the primary group. Therefore, the user can be considered to be a member of this group even if no 'member' or 'memberOf' attributes are present.
adminCount | Indicates that a given object has had its ACLs changed to a more secure value by the system because it was a member of one of the administrative groups (directly or transitively). Basically, anyone with adminCount=1 is or was a privileged user of some sort.
objectSid | The SID 
sAMAccountName | The username (the logon name used to support clients and servers running earlier versions of the operating system.)
sAMAccountType | This attribute contains information about every account type object. This is parsed by ADOffline.
objectCategory | "An object class name used to group objects of this or derived classes."
operatingSystem | The named operating system; only relevant to computers for obvious reasons.
operatingSystemVersion | The version of the operating system.
operatingSystemServicePack | The identifier of the latest service pack installed
managedBy | The distinguished name of the user that is assigned to manage this object. Useful as a starting point when looking for managed groups with additional permissions.
info | One of the general fields available in AD. Sometimes used to store interesting information relating to a user/group/computer.
department | The department to which the user belongs.
company | The name of the company.
homeDirectory | The default home directory location which is mapped to the user's home directory. Useful to identify file servers quickly on the network, but be mindful of DFS (i.e. \\domain\home\user vs \\fileserver\home\user).
userPrincipalName | Usually the user's e-mail address.
manager | The user's manager; useful for generating organisational charts. Note that this is different from the 'managedBy' attribute; the manager seems to be for display/organisation chart purposes only.
mail | Another field that contains the user's e-mail address.
groupType | Contains a set of flags that define the type and scope of a group object. 

### The Database Tables

Internally, the database has two tables which are created automatically using the statements below.

```
CREATE TABLE raw_users ('objectClass','dn','title', 'cn','sn','description','instanceType','displayName','name','dNSHostName','userAccountControl','badPwdCount','primaryGroupID','adminCount','objectSid','sid','rid','sAMAccountName','sAMAccountType', 'objectCategory','operatingSystem','operatingSystemServicePack','operatingSystemVersion','managedBy','givenName','info','department','company','homeDirectory','userPrincipalName','manager','mail','groupType');

CREATE TABLE raw_memberof ('dn_group' TEXT NOT NULL,'dn_member' TEXT NOT NULL, PRIMARY KEY('dn_group','dn_member'));
```

The first table (raw_users) holds the basic information retrieved from LDAP as discussed in the table above. The second table stores any DNs referenced by a member or memberOf attribute. For example, if UserA and UserB are members of GroupX, raw_memberof will contain:

dn_group | dn_member
---|---
GroupX | UserA
GroupX | UserB

(in reality, it will contain DNs rather than usernames, but this illustrates the point). The idea is that the raw_memberof table can be joined with the raw_users table to be able to determine who is a member of what.

### The Database Views

In order to make this easier to interact with, a number of views; a view is essentially a table which is generated at runtime from a SQL query. 

Name | Purpose
---|---
view_raw_users | This view (which can be treated as a table for the purposes of querying) shows the contents of the raw_users table, but also adds a number of additional columns to split up the userAccountControl and sAMAccountType values. For example, you could search for ADS_UF_LOCKOUT=1 instead of (userAccountControl&00000010).
view_groups | This will effectively display the contents of the view above, restricting the results to groups only, and adding in the groupType parameter parsing. In effect, this can be used to list all stored information about all groups.
view_users | Displays the contents of the view_raw_users table, but only shows users (rather than groups and computers).
view_computers | As above, but only shows computers.
view_groupmembers | This uses the raw_memberof table to (internally) join the users table with itself. The effect is being able to search by all attributes on a group or its members. The group fields are denoted by the prefix group_ and the member fields are denoted by the prefix member_. For example, 'SELECT member_cn FROM view_groupmembers where group_cn = "Domain Admins"' would display all members of the Domain Admins group, taking into account nested groups.
view_activegroupusers | This restricts the output of view_groupmembers to users who are not locked and not disabled. The same query as above, but only returning names of users who are active would be 'select member_cn from view_activegroupusers where group_cn = "Domain Admins"'

This probably looks quite confusing and inefficient, and both are true. However, designing it this way does make it very powerful; it enables almost any sensible search to be performed offline which is of particular use during simulated attacks because you can identify high value accounts completely offline, and get a good idea of the internals of the target domain without running repeated queries.

I would encourage you to take the time to get used to this. I have provided a description of each of the fields available in the database below and, below that, some examples of common queries.

## Examples
