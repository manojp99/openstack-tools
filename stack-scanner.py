import pwd
import os
import grp


def check_path_permissions(paths,component):
    for path in paths:
        stat_info = os.stat(path)
        uid = stat_info.st_uid
        gid = stat_info.st_gid
        user = pwd.getpwuid(uid)[0]
        group = grp.getgrgid(gid)[0]
        if (user != 'stack' or group != 'stack'):
            print("Warning: Check user permissions for : "+path)
        if (int(oct(stat_info.st_mode)[-3:]) < 640):
            print("Warning: Check restrictions on : "+path)

######## Identity (keystone) ##########
print("Checking Keystone...")

paths = ['/etc/keystone/keystone.conf','/etc/keystone/','/etc/keystone/keystone-uwsgi-public.ini']

check_path_permissions(paths,'keystone')

keystone_conf = open('/etc/keystone/keystone.conf','r')

max_request_body_size = False
admin_token = False
fernet_provider = False
insecure_debug = False

for config in keystone_conf:
    if 'max_request_body_size' in config:
        max_request_body_size = True
    if 'admin_token' in config:
        admin_token = True
    if 'provider' in config:
        if 'fernet' == config.split('=')[1].strip():
            fernet_provider = True
    if 'debug' in config:
        if 'False' == config.split('=')[1].strip():
            insecure_debug = True

if not max_request_body_size:
    print("Warning: Max request size not set")
if not admin_token:
    print("Warning: Admin token not set")
if not fernet_provider:
    print("Error: Provider is not fernet")
if not insecure_debug:
    print("Warning: Debug is on")
        

######### Dashboard #############
print("\nChecking Horizon....")

paths = ['/opt/stack/horizon/openstack_dashboard/local/local_settings.py']

check_path_permissions(paths,'horizon')

dashboard_conf = open('/opt/stack/horizon/openstack_dashboard/local/local_settings.py','r')

iframe_embed = False
csrf_cookie = False
session_cookie = False
session_cookie_http = False
password_auto = False
secure_proxy = False

for config in dashboard_conf:
    if '#' in config:
        continue
    if 'DISALLOW_IFRAME_EMBED' in config:
        if 'True' == config.split('=')[1].strip():
            iframe_embed = True
    if 'CSRF_COOKIE_SECURE' in config:
        if 'True' == config.split('=')[1].strip():
            csrf_cookie = True
    if 'SESSION_COOKIE_SECURE' in config:
        if 'True' == config.split('=')[1].strip():
            session_cookie = True
    if 'SESSION_COOKIE_HTTPONLY' in config:
        if 'True' == config.split('=')[1].strip():
            session_cookie_http = True
    if 'PASSWORD_AUTOCOMPLETE' in config:
        if 'off' == config.split('=')[1].strip():
            password_auto = True
    if 'SECURE_PROXY_SSL_HEADER' in config:
        if 'http' in confing and 'HTTP_X_FORWARDED_PROTO' in config:
            secure_proxy = True

if not iframe_embed:
    print("Warning: IFrame embedding is allowed")
if not csrf_cookie:
    print("Warning: CSRF cookie is not secured")
if not session_cookie:
    print("Warning: Session cookie is not secured")
if not session_cookie_http:
    print("Warning: Session cookie in not http only")
if not password_auto:
    print("Warning: Auto password is set")
if not secure_proxy:
    print("Warning: SSL Proxy is not secure")

################# Compute ########################
print("\nChecking Nova....")
paths = ['/etc/nova/nova.conf','/etc/nova/api-paste.ini','/etc/nova/nova-api-uwsgi.ini','/etc/nova/rootwrap.conf']
check_path_permissions(paths,'nova')

auth_strategy = False
auth_url = False

nova_conf = open('/etc/nova/nova.conf','r')
for config in nova_conf:
    if '#' in config:
        continue
    if 'auth_strategy' in config:
       if 'keystone' == config.split('=')[1].strip():
            auth_strategy = True
    if 'auth_url' in config:
        if 'identity' in config:
            auth_url = True

if not auth_strategy:
    print("Warning: Keystone is not set for authorization")
if not auth_url:
    print("Warning: Identity service is not for auth url")


################ Block Storage ##################
print("\nChecking Cinder....")
auth_strategy = False
auth_url = False
max_request_body = False
backend = False

rp = '/etc/cinder/'
paths = [rp+'api-paste.ini',rp+'cinder.conf',rp+'cinder-api-uwsgi.ini',rp+'rootwrap.conf']
check_path_permissions(paths,'cinder')
cinder_conf = open('/etc/cinder/cinder.conf','r')
for config in cinder_conf:
    if 'auth_strategy' in config:
       if 'keystone' == config.split('=')[1].strip():
            auth_strategy = True
    if 'auth_url' in config:
        if 'identity' in config:
            auth_url = True
    if 'max_request_body_size' in config:
        max_request_body_size = True
    if 'backend' in config:
        backend = True

if not auth_strategy:
    print("Warning: Keystone is not set for authorization")
if not auth_url:
    print("Warning: Identity service is not for auth url")
if not max_request_body_size:
    print("Warning: Limit is not set on maximum request body")
if not backend:
    print("Warning: Backend caching is enabled")


############# Image storage ###########
print("\nChecking Glance....")
auth_strategy = False
auth_url = False
rp = '/etc/glance/'
paths = [rp+'glance-api-paste.ini',rp+'glance-api.conf',rp+'glance-uwsgi.ini',rp+'rootwrap.conf',rp+'glance-cache.conf',rp+'glance-image-import.conf']
check_path_permissions(paths,'glance')
glance_conf = open('/etc/glance/glance-api.conf','r')
for config in glance_conf:
    if 'auth_strategy' in config:
       if 'keystone' == config.split('=')[1].strip():
            auth_strategy = True
    if 'auth_url' in config:
        if 'identity' in config:
            auth_url = True

if not auth_strategy:
    print("Warning: Keystone is not set for authorization")
if not auth_url:
    print("Warning: Identity service is not for auth url")

############# Networking ###########
print("\nChecking Neutron....")
auth_strategy = False
auth_url = False
use_ssl = False
rp = '/etc/neutron/'
paths = [rp+'api-paste.ini',rp+'neutron.conf',rp+'neutron_ovn_metadata_agent.ini',rp+'rootwrap.conf']
check_path_permissions(paths,'neutron')
glance_conf = open('/etc/neutron/neutron.conf','r')
for config in glance_conf:
    if '#' in config:
        continue
    if 'auth_strategy' in config:
       if 'keystone' == config.split('=')[1].strip():
            auth_strategy = True
    if 'auth_url' in config:
        if 'identity' in config:
            auth_url = True
    if 'use_ssl' in config:
        if 'true' == config.split('=')[1].strip():
            use_ssl = True

if not auth_strategy:
    print("Warning: Keystone is not set for authorization")
if not auth_url:
    print("Warning: Identity service is not for auth url")
if not use_ssl:
    print("Warning: SSL is disabled")
