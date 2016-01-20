import time
import pprint
import tempfile
import sqlite3
import re
import sys

# This function looks for "x: y" in an LDIF
# file and effectively splits them up using a regex
def match_param(line,param):
    var = re.match('^'+param+'::?\s([^$]+)\s*$', line.strip())
    if var != None:
        return var.group(1).strip()

    return None

# This updates the dict (if it doesn't already exist)
# with a name/value pair (and adds it to a list)
def update_struct(struct,name,val):
    if val==None:
        return False

    if not name in struct:
        struct[name] = []
    struct[name].append(val)
    return True

# This function processes the completed struct. For example,
# we have just seen a new 'dn' and therefore must have finished 
# the last block
def process_struct(struct,sql):

    # If there isn't a DN in there, we aren't interested
    if not 'dn' in struct or not 'objectClass' in struct or not 'user' in struct['objectClass']:
        return

    insert_into_db(struct,sql)
    return

# Build the SQL database schema
def build_db_schema(sql):
    
    c = sql.cursor()

    # Create the tables
    c.execute('''CREATE TABLE raw_users
                 ('objectClass','dn','cn','sn','description','instanceType','displayName','name','dNSHostName','userAccountControl','badPwdCount','primaryGroupID','adminCount','objectSid','sid','rid','sAMAccountName','sAMAccountType',
                 'objectCategory','operatingSystem','operatingSystemServicePack','operatingSystemVersion','managedBy','givenName','info','department','company','homeDirectory','userPrincipalName',
                 'manager','mail','groupType')''') 
    c.execute("CREATE TABLE raw_memberof ('dn_group','dn_member')")

    sql.commit()
    return
 
# Build the SQL database schema
def fix_db_indices(sql):
    
    c = sql.cursor()

    # Create the indicies
    c.execute("CREATE UNIQUE INDEX raw_users_dn on raw_users (dn)")
    c.execute("CREATE INDEX raw_users_dnshostname on raw_users (objectClass,dNSHostName)")
    c.execute("CREATE INDEX raw_users_samaccountname on raw_users (objectClass,sAMAccountName)")
    c.execute("CREATE UNIQUE INDEX raw_memberof_group_user on raw_memberof('dn_group','dn_member')")
    c.execute("CREATE UNIQUE INDEX raw_memberof_user_group on raw_memberof('dn_member','dn_group')")

    sql.commit()
    return

def create_views(sql):
    
    c = sql.cursor()

    # Generate the main view with calculated fields
    c.execute('''CREATE VIEW view_raw_users AS select objectClass, dn, cn, sn, description, instanceType, displayName, name, dNSHostName, userAccountControl, badPwdCount, primaryGroupID, adminCount, objectSid, sid, rid, sAMAccountName, sAMAccountType, objectCategory, managedBy, givenName, info, department, company, homeDirectory, userPrincipalName, manager, mail, operatingSystem, operatingSystemVersion, operatingSystemServicePack, groupType,
     (CASE (userAccountControl&0x00000001) WHEN (0x00000001) THEN 1 ELSE 0 END) AS ADS_UF_SCRIPT,
     (CASE (userAccountControl&0x00000002) WHEN (0x00000001) THEN 1 ELSE 0 END) AS ADS_UF_ACCOUNTDISABLE,
	 (CASE (userAccountControl&0x00000008) WHEN (0x00000001) THEN 1 ELSE 0 END) AS ADS_UF_HOMEDIR_REQUIRED,
	 (CASE (userAccountControl&0x00000010) WHEN (0x00000001) THEN 1 ELSE 0 END) AS ADS_UF_LOCKOUT,
	 (CASE (userAccountControl&0x00000020) WHEN (0x00000001) THEN 1 ELSE 0 END) AS ADS_UF_PASSWD_NOTREQD,
	 (CASE (userAccountControl&0x00000040) WHEN (0x00000001) THEN 1 ELSE 0 END) AS ADS_UF_PASSWD_CANT_CHANGE,
	 (CASE (userAccountControl&0x00000080) WHEN (0x00000001) THEN 1 ELSE 0 END) AS ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED,
	 (CASE (userAccountControl&0x00000100) WHEN (0x00000001) THEN 1 ELSE 0 END) AS ADS_UF_TEMP_DUPLICATE_ACCOUNT,
	 (CASE (userAccountControl&0x00000200) WHEN (0x00000001) THEN 1 ELSE 0 END) AS ADS_UF_NORMAL_ACCOUNT,
	 (CASE (userAccountControl&0x00000800) WHEN (0x00000001) THEN 1 ELSE 0 END) AS ADS_UF_INTERDOMAIN_TRUST_ACCOUNT,
	 (CASE (userAccountControl&0x00001000) WHEN (0x00000001) THEN 1 ELSE 0 END) AS ADS_UF_WORKSTATION_TRUST_ACCOUNT,
	 (CASE (userAccountControl&0x00002000) WHEN (0x00000001) THEN 1 ELSE 0 END) AS ADS_UF_SERVER_TRUST_ACCOUNT,
	 (CASE (userAccountControl&0x00010000) WHEN (0x00000001) THEN 1 ELSE 0 END) AS ADS_UF_DONT_EXPIRE_PASSWD,
	 (CASE (userAccountControl&0x00020000) WHEN (0x00000001) THEN 1 ELSE 0 END) AS ADS_UF_MNS_LOGON_ACCOUNT,
	 (CASE (userAccountControl&0x00040000) WHEN (0x00000001) THEN 1 ELSE 0 END) AS ADS_UF_SMARTCARD_REQUIRED,
	 (CASE (userAccountControl&0x00080000) WHEN (0x00000001) THEN 1 ELSE 0 END) AS ADS_UF_TRUSTED_FOR_DELEGATION,
	 (CASE (userAccountControl&0x00100000) WHEN (0x00000001) THEN 1 ELSE 0 END) AS ADS_UF_NOT_DELEGATED,
	 (CASE (userAccountControl&0x00200000) WHEN (0x00000001) THEN 1 ELSE 0 END) AS ADS_UF_USE_DES_KEY_ONLY,
	 (CASE (userAccountControl&0x00400000) WHEN (0x00000001) THEN 1 ELSE 0 END) AS ADS_UF_DONT_REQUIRE_PREAUTH,
	 (CASE (userAccountControl&0x00800001) WHEN (0x00000001) THEN 1 ELSE 0 END) AS ADS_UF_PASSWORD_EXPIRED,
	 (CASE (userAccountControl&0x01000000) WHEN (0x00000001) THEN 1 ELSE 0 END) AS ADS_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION,
	 CASE WHEN (sAMAccountType==0) THEN 1 ELSE 0 END AS SAM_DOMAIN_OBJECT,
	 CASE WHEN (sAMAccountType==0x10000000) THEN 1 ELSE 0 END AS SAM_GROUP_OBJECT,
	 CASE WHEN (sAMAccountType==0x10000001) THEN 1 ELSE 0 END AS SAM_NON_SECURITY_GROUP_OBJECT,
	 CASE WHEN (sAMAccountType==0x20000000) THEN 1 ELSE 0 END AS SAM_ALIAS_OBJECT,
	 CASE WHEN (sAMAccountType==0x20000001) THEN 1 ELSE 0 END AS SAM_NON_SECURITY_ALIAS_OBJECT,
	 CASE WHEN (sAMAccountType==0x30000000) THEN 1 ELSE 0 END AS SAM_NORMAL_USER_ACCOUNT,
	 CASE WHEN (sAMAccountType==0x30000001) THEN 1 ELSE 0 END AS SAM_MACHINE_ACCOUNT,
	 CASE WHEN (sAMAccountType==0x30000002) THEN 1 ELSE 0 END AS SAM_TRUST_ACCOUNT,
	 CASE WHEN (sAMAccountType==0x40000000) THEN 1 ELSE 0 END AS SAM_APP_BASIC_GROUP,
	 CASE WHEN (sAMAccountType==0x40000001) THEN 1 ELSE 0 END AS SAM_APP_QUERY_GROUP,
	 CASE WHEN (sAMAccountType==0x7fffffff) THEN 1 ELSE 0 END AS SAM_ACCOUNT_TYPE_MAX FROM raw_users''')

    # Add additional fields to the group one
    c.execute('''CREATE VIEW view_groups AS select view_raw_users.*,
     (CASE (groupType&0x00000001) WHEN (0x00000001) THEN 1 ELSE 0 END) AS GROUP_CREATED_BY_SYSTEM,
     (CASE (groupType&0x00000002) WHEN (0x00000002) THEN 1 ELSE 0 END) AS GROUP_SCOPE_GLOBAL,
     (CASE (groupType&0x00000004) WHEN (0x00000004) THEN 1 ELSE 0 END) AS GROUP_SCOPE_LOCAL,
     (CASE (groupType&0x00000008) WHEN (0x00000008) THEN 1 ELSE 0 END) AS GROUP_SCOPE_UNIVERSAL,
     (CASE (groupType&0x00000010) WHEN (0x00000010) THEN 1 ELSE 0 END) AS GROUP_SAM_APP_BASIC,
     (CASE (groupType&0x00000020) WHEN (0x00000020) THEN 1 ELSE 0 END) AS GROUP_SAM_APP_QUERY,
     (CASE (groupType&0x80000000) WHEN (0x80000000) THEN 1 ELSE 0 END) AS GROUP_SECURITY,
     (CASE (groupType&0x80000000) WHEN (0x80000000) THEN 0 ELSE 1 END) AS GROUP_DISTRIBUTION FROM view_raw_users WHERE objectClass = 'group' ''')

    # Create the user and computer views. In effect it is the same table though.
    c.execute("CREATE VIEW view_users AS select view_raw_users.* FROM view_raw_users WHERE objectClass = 'user'")
    c.execute("CREATE VIEW view_computers AS select view_raw_users.* FROM view_raw_users WHERE objectClass = 'computer'")

    sql.commit()
    return

def insert_into_db(struct,sql):
    c = sql.cursor()
    ldap_single_params = ['cn','sn','description','instanceType','displayName','name','dNSHostName','userAccountControl','badPwdCount','primaryGroupID','adminCount','objectSid','sAMAccountName','sAMAccountType','objectCategory','operatingSystem','operatingSystemServicePack','operatingSystemVersion','managedBy','givenName','info','department','company','homeDirectory','userPrincipalName','manager','mail','groupType']
    ldap_values = []
    for ind in ldap_single_params:
        ldap_values.append(safe_struct_get(struct,ind))

    # Raw_users contains everything
    sql_statement = "insert into raw_users ('objectClass','dn','cn','sn','description','instanceType','displayName','name','dNSHostName','userAccountControl','badPwdCount','primaryGroupID','adminCount','objectSid','sAMAccountName','sAMAccountType','objectCategory','operatingSystem','operatingSystemServicePack','operatingSystemVersion','managedBy','givenName','info','department','company','homeDirectory','userPrincipalName','manager','mail','groupType') VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
    ldap_values.insert(0,struct['dn'])

    # Make sure that this is a user, group or computer
    oc = None
    if 'computer' in struct['objectClass']:
        oc = 'computer'
    elif 'group' in struct['objectClass']:
        oc = 'group'
    elif 'user' in struct['objectClass']:
        oc = 'user'
    else:
        return

    ldap_values.insert(0,oc)
    c.execute(sql_statement, ldap_values)

    if 'memberOf' in struct:
        for m in struct['memberOf']:
            sql_memberof = 'replace into raw_memberof (dn_group,dn_member) VALUES (?,?)'
            c.execute(sql_memberof, [m,struct['dn']])

    sql.commit()
    return

def safe_struct_get(struct,name):
    if not struct:
        return None
    
    if not name in struct:
        return None

    if not struct[name][0]:
        return None

    return struct[name][0]

def log(strval):
    sys.stdout.write('['+time.strftime("%d/%b/%y %H:%M:%S")+'] '+strval)
    sys.stdout.flush()
    return

# Create the SQLite3 database
sys.stdout.write("AD LDAP to SQLite Offline Parser\nStuart Morgan (@ukstufus) <stuart.morgan@mwrinfosecurity.com>\n\n")
log("Creating database: ")
db_file = tempfile.NamedTemporaryFile(delete=False)
db_filename = db_file.name+'.'+time.strftime('%Y%m%d%H%M%S')+'.ad-ldap.db'
db_file.close()
sql = sqlite3.connect(db_filename)
build_db_schema(sql)
create_views(sql)
sys.stdout.write(db_filename+"\n")

sql.close()
sys.exit(0)

log("Reading LDIF..")
# Open the LDAP file and read its contents
f = open("ldap.file","r")
lines = f.readlines()
sys.stdout.write(".done\n")

# Create an initial object
current_dn = {}

# The list of ldap parameters to save
ldap_params = ['objectClass','cn','sn','description','instanceType','displayName','member','memberOf','name','dNSHostName','userAccountControl','badPwdCount','primaryGroupID','adminCount','objectSid','sAMAccountName','sAMAccountType','objectCategory','operatingSystem','operatingSystemServicePack','operatingSystemVersion','managedBy','givenName','info','department','company','homeDirectory','sIDHistory','userPrincipalName','manager','mail','groupType']

log("Parsing LDIF.")
# Go through each line in the LDIF file
for line in lines:

    # If it starts with DN, its a new "block"
    val = match_param(line,'dn')
    if val != None: 
        process_struct(current_dn,sql)
        current_dn = {}
        current_dn['dn'] = val
        continue

    for p in ldap_params:
        update_struct(current_dn, p, match_param(line,p))
    
# We are at the last line, so process what
# is left as a new block
process_struct(current_dn,sql)
sys.stdout.write(".done\n")

log("Applying indices..")
fix_db_indices(sql)
sys.stdout.write(".done\n")

sql.close()
log("Completed")
