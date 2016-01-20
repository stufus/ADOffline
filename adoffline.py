import time
import pprint
import tempfile
import sqlite3
import re
import sys

# This function looks for "x: y" in an LDIF
# file and effectively splits them up using a regex
def match_param(line,param):
    var = re.match('^'+param+'::?\s([^$]+)\s*$', line)
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
    sys.stdout.write('+')
    sys.stdout.flush()
    return

# Build the SQL database schema
def build_db_schema(sql):
    
    c = sql.cursor()
    c.execute('''CREATE TABLE raw_users
                 ('dn','cn','sn','description','instanceType','displayName','name','dNSHostName','userAccountControl','badPwdCount','primaryGroupID','adminCount','objectSid','sAMAccountName','sAMAccountType',
                 'objectCategory','operatingSystem','operatingSystemServicePack','operatingSystemVersion','managedBy','givenName','info','department','company','homeDirectory','sIDHistory','userPrincipalName',
                 'manager','mail','groupType')''') 
    c.execute('''CREATE TABLE raw_memberof ('dn_group','dn_user')''')
    sql.commit()
    return
 
def insert_into_db(struct,sql):
    c = sql.cursor()
    ldap_single_params = ['cn','sn','description','instanceType','displayName','name','dNSHostName','userAccountControl','badPwdCount','primaryGroupID','adminCount','objectSid','sAMAccountName','sAMAccountType','objectCategory','operatingSystem','operatingSystemServicePack','operatingSystemVersion','managedBy','givenName','info','department','company','homeDirectory','userPrincipalName','manager','mail','groupType']
    ldap_values = []
    for ind in ldap_single_params:
        ldap_values.append(safe_struct_get(struct,ind))

    sql_statement = "insert into raw_users ('dn','cn','sn','description','instanceType','displayName','name','dNSHostName','userAccountControl','badPwdCount','primaryGroupID','adminCount','objectSid','sAMAccountName','sAMAccountType','objectCategory','operatingSystem','operatingSystemServicePack','operatingSystemVersion','managedBy','givenName','info','department','company','homeDirectory','userPrincipalName','manager','mail','groupType') VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
    ldap_values.insert(0,struct['dn'])
    c.execute(sql_statement, ldap_values)

    if 'memberOf' in struct:
        for m in struct['memberOf']:
            sql_memberof = 'replace into raw_memberof (dn_group,dn_user) VALUES (?,?)'
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
sys.stdout.write("AD LDAP to SQLite Offline Parser\nStuart Morgan @ukstufus <stuart.morgan@mwrinfosecurity.com>\n\n")
log("Creating database: ")
db_file = tempfile.NamedTemporaryFile(delete=False)
db_filename = db_file.name+'.'+time.strftime('%Y%m%d%H%M%S')+'.ad-ldap.db'
db_file.close()
sql = sqlite3.connect(db_filename)
build_db_schema(sql)
sys.stdout.write(db_filename+"\n")

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
sql.close()
sys.stdout.write(".done\n")
log("Completed")
