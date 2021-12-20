import os
import pytest

#pip install ansible
#py.test --hosts=web --ansible-inventory=inventory --connection=ansible test_web.py
#$ py.test --hosts=all # tests all inventory hosts
#$ py.test --hosts='ansible://host1,ansible://host2'
#$ py.test --hosts='ansible://web*'
# will use the default namespace and default container
#$ py.test --hosts='kubectl://mypod-a1b2c3'
# specify container name and namespace
#$ py.test --hosts='kubectl://somepod-2536ab?container=nginx&namespace=web'

import testinfra.utils.ansible_runner

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']).get_hosts('all')

testinfra_hosts = ["localhost", "root@webserver:2222"]
def test_foo(host):
    [....]



@pytest.mark.parametrize('pkg', [
    'krb5-libs',
    'krb5-server',
    'krb5-workstation'
])
def test_packages(host, pkg):
    package = host.package(pkg)

    assert package.is_installed


def test_kdc_conf(host):
    kdc_conf = host.file("/var/kerberos/krb5kdc/kdc.conf")

    assert kdc_conf.exists
    assert kdc_conf.is_file
    assert kdc_conf.user == 'root'
    assert kdc_conf.group == 'root'
    assert oct(kdc_conf.mode) == '0600'


@pytest.mark.parametrize('content', [
    "kdc_ports = 88",
    "kdc_tcp_ports = 88",
    "EXAMPLE.COM = {",
    "supported_enctypes = aes256-cts:normal aes128-cts:normal des3-hmac-sha1:normal arcfour-hmac:normal "
    "des-hmac-sha1:normal des-cbc-md5:normal des-cbc-crc:normal",
    "max_life = 24h",
    "max_renewable_life = 7d"
])
def test_kdc_conf_content(host, content):
    kdc_conf = host.file("/var/kerberos/krb5kdc/kdc.conf")

    assert kdc_conf.contains(content)


def test_kadm5_acl(host):
    kadm5_acl = host.file("/var/kerberos/krb5kdc/kadm5.acl")

    assert kadm5_acl.exists
    assert kadm5_acl.is_file
    assert kadm5_acl.user == 'root'
    assert kadm5_acl.group == 'root'
    assert oct(kadm5_acl.mode) == '0600'


@pytest.mark.parametrize('content', [
    "*/admin@EXAMPLE.COM     *",
    "cloudera-scm@EXAMPLE.COM admilc"
])
def test_kadm5_acl_content(host, content):
    kadm5_acl = host.file("/var/kerberos/krb5kdc/kadm5.acl")

    assert kadm5_acl.contains(content)


def test_krb5_conf(host):
    krb5_conf = host.file("/etc/krb5.conf")

    assert krb5_conf.exists
    assert krb5_conf.is_file
    assert krb5_conf.user == 'root'
    assert krb5_conf.group == 'root'
    assert oct(krb5_conf.mode) == '0644'


def test_nginx_is_installed(host):
    nginx = host.package("nginx")
    assert nginx.is_installed
    assert nginx.version.startswith("1.2")


def test_nginx_running_and_enabled(host):
    nginx = host.service("nginx")
    assert nginx.is_running
    assert nginx.is_enabled


@pytest.mark.parametrize('content', [
    "default_realm = EXAMPLE.COM",
    "ticket_lifetime = 24h",
    "renew_lifetime = 7d",
    "EXAMPLE.COM = {",
    "kdc = centos-7.example.com",
    "admin_server = centos-7.example.com",
    ".example.com = EXAMPLE.COM",
    "example.com = EXAMPLE.COM"
])
def test_krb5_conf_content(host, content):
    krb5_conf = host.file("/etc/krb5.conf")

    assert krb5_conf.contains(content)


@pytest.mark.parametrize('file', [
    "/var/kerberos/db_created",
    "/var/kerberos/admin_created",
    "/var/kerberos/krb5kdc/principal"
])
def test_files(host, file):
    file = host.file(file)

    assert file.exists


@pytest.mark.parametrize('svc', [
  'krb5kdc',
  'kadmin'
])
def test_services(host, svc):
    service = host.service(svc)

    assert service.is_running
    assert service.is_enabled
