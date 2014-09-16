#!/usr/bin/python
#
# Copyright 2010 (C) VMware, Inc.  All rights reserved.
#
# config-page.py:
#
#	Backend code for VAMI Web UI that interacts
#
#       Currently it has methods to deal with
#               - initialize SSO server
#               - display SSO server status
#               - manage SSO host name
#

import subprocess, os, vami, collections, tempfile
import re

SSL_STORE_FILE = "/usr/lib/vmware-sts/conf/ssoserver.p12"
SSL_STORE_PWD = "changeme"
SSL_STORE_ALIAS = "ssoserver"

hostMatcher = None

def matchHost(host):
    global hostMatcher
    if not hostMatcher:
        hostMatcher = re.compile(
            r'((?P<scheme>https?)(://))?((?P<host>(\\[(.*?)\\]|([^/ :]+)))(:(?P<port>[0-9]*))?)',
            re.IGNORECASE
        )
    return hostMatcher.match(host)

def isSsoInitialized():
    return os.path.exists('/usr/lib/vmware-sts')


def checkIfSsoIsInitialized():
    if not isSsoInitialized():
        raise Exception('SSO is not initialized.')


def callOpenSSL(args, sendText=None, errorMessage='Error calling OpenSSL tools.'):
    cmd = ['/usr/bin/openssl']
    cmd.extend(args)
    in_stream = None
    if sendText:
        in_stream = subprocess.PIPE
    vami.log_info('Executing %s' % cmd)
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=in_stream, close_fds=True)
    if in_stream:
        process.stdin.write(sendText)
        process.stdin.close()
    if process.wait():
        raise Exception(errorMessage)
    return process.stdout.read()


def getSsoStatus():
    if isSsoInitialized():
        process = subprocess.Popen(['/etc/init.d/vmware-stsd', 'status'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        process.wait() # tc-server always returns 0
        out = process.stdout.read()
        out = out.split('..')
        if len(out) < 1:
            raise Exception('Cannot determine SSO status.')
        out = out[len(out) - 1]
        return out.strip().upper()
    return 'NOT INITIALIZED'


def importCertificate(certificate, key, passphrase):
    args = ['rsa']
    if len(passphrase):
        args.extend(['-passin', 'pass:%s' % passphrase])
    vami.log_info("Reading input keys...")
    key = callOpenSSL(args, key, 'Unable to load Private Key.')
    vami.log_info("Reading input keys succeeded.")
    pem = tempfile.NamedTemporaryFile(prefix='pem')
    tk = tempfile.NamedTemporaryFile(prefix='pkcs', delete=False)
    pem.write('%s\n%s' % (key, certificate))
    pem.flush()
    args = ['pkcs12', '-export', '-out', tk.name,
            '-name', SSL_STORE_ALIAS, '-password', 'pass:%s' % SSL_STORE_PWD, '-in', pem.name]
    if certificate.count('-----BEGIN CERTIFICATE-----') > 1:
        crt = tempfile.NamedTemporaryFile(prefix='cert')
        crt.write(certificate)
        crt.flush()
        args.extend(['-chain', '-CAfile', crt.name])
    callOpenSSL(args, errorMessage='Unable to create SSL key store.')
    tk.close()
    os.rename(tk.name, SSL_STORE_FILE)


def generateCertificate(countryCode, commonName, org, orgUnit=None, city=None, state=None, emailAddress=None):
    def filterValue(value):
        if value and len(value):
            return value
        return '.'

    tmp = tempfile.NamedTemporaryFile()
    pwd = 'pass:123456'
    vami.log_info("Generating RSA private key...")
    callOpenSSL(['genrsa', '-aes256', '-passout', pwd, '-out', tmp.name, '2048'],
        errorMessage="Error generating Private Key.")
    vami.log_info("RSA private key generated successfully.")
    csrData = '%s\n%s\n%s\n%s\n%s\n%s\n%s\n.\n.\n' % (
        filterValue(countryCode),
        filterValue(state),
        filterValue(city),
        filterValue(org),
        filterValue(orgUnit),
        filterValue(commonName),
        filterValue(emailAddress)
        )
    vami.log_info("Creating CSR...")
    csr = callOpenSSL(['req', '-new', '-key', tmp.name, '-passin', pwd, '-utf8'],
        csrData, "Error creating Certificate Signing Request.")
    vami.log_info("CSR created.")
    vami.log_info("Generating SSL certificate...")
    certificate = callOpenSSL(['x509', '-req', '-days', '365', '-signkey', tmp.name, '-passin', pwd],
        csr, "Error creating certificate.")
    vami.log_info("SSL certificate generated successfully.")
    key = callOpenSSL(['rsa', '-in', tmp.name, '-passin', pwd])
    vami.log_info("Private key exported successfully.")
    pem = '%s\n%s' % (key, certificate)
    callOpenSSL(['pkcs12', '-export',
                 '-out', SSL_STORE_FILE,
                 '-name', SSL_STORE_ALIAS,
                 '-password', 'pass:%s' % SSL_STORE_PWD], pem, 'Unable to create SSL key store.')
    tmp.close()
    vami.log_info("PKCS12 key store successfully created.")


def callDomainJoin(args, defaultErrorMessage='Error invoking Active Directory tools.'):
    cmd = ['/opt/likewise/bin/domainjoin-cli']
    if isinstance(args, basestring):
        cmd.append(args)
    elif isinstance(args, collections.Iterable):
        cmd.extend(args)
    else:
        raise Exception('Supported parameters are single string or list of strings.')
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
    if process.wait():
        message = process.stderr.read()
        if not message:
            message = defaultErrorMessage
            data = process.stdout.read()
            if data:
                data = data.splitlines()
                if len(data) > 0:
                    data = data[len(data) - 1].strip()
                    if data:
                        message = data
        raise Exception(message)
    vami.callExternalCommand(['/etc/init.d/vmware-sts-idmd', 'restart'])
    return process.stdout.read()


def parseKeyEqualsVal(data, separator='='):
    result = {}
    if isinstance(data, basestring):
        lines = data.splitlines()
        for line in lines:
            s = line.split(separator, 1)
            if len(s) == 2:
                key = s[0].strip().lower()
                if len(key) > 0:
                    value = s[1].strip()
                    if len(value) > 0:
                        result[key] = value
    return result


def getActiveDirectoryStatus():
    data = callDomainJoin('query')
    return parseKeyEqualsVal(data)


def callCmd(args):
    process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
    (stdout, stderr) = process.communicate()
    return (process.returncode, stdout, stderr)


def checkNetworkSettings(domain):
    msgs = []

    (_, stdout, _) = callCmd(['/opt/likewise/bin/lw-get-dc-name', domain])

    if stdout:
        data = parseKeyEqualsVal(stdout)
        name = data['pszdomaincontrollername']
        address = data['pszdomaincontrolleraddress']

        (statusName, _, _) = callCmd(['getent', 'hosts', name])
        (statusIP, _, _) = callCmd(['getent', 'hosts', address])
        if statusName != 0:
            msgs.append("Warning: Cannot resolve domain controller hostname %s." % name)
            vami.log_info("Warning: Cannot resolve domain controller hostname %s." % name)
        elif statusIP != 0:
            msgs.append("Warning: Cannot resolve domain controller IP address %s." % address)
            vami.log_info("Warning: Cannot resolve domain controller IP address %s." % address)
            # can resolve both ip and name
        else:
            # msgs.append("Can resolve both hostname and IP of the DC (%s, %s)." % (name, address))
            vami.log_info("Can resolve both hostname and IP of the DC (%s, %s)." % (name, address))

    data = callDomainJoin(['join', '--preview', domain])
    data = parseKeyEqualsVal(data, ':')

    if not 'with computer dns name' in data:
        msgs.append("Warning: Cannot get this server DNS name from domain controller %s." % domain)
    else:
        hostDC = data['with computer dns name']
        vami.log_info("hostDC '%s'" % hostDC)
        (_, hostname, _) = callCmd(['hostname'])
        vami.log_info("hostname '%s'" % hostname)

        hostname = hostname.lower().strip()
        hostDC = hostDC.lower().strip()

        if hostDC != hostname:
            msgs.append(
                "Warning: According to the domain controller the host name of the server should be %s." % hostDC)

    return msgs

DEFAULT_DOMAIN_NAME = 'vsphere.local'

# todo: actual SSO domain should be returned here
def getSsoDomain():
    return DEFAULT_DOMAIN_NAME


def getSsoHost(removePort=False):
    file = open(SSO_HOST_CONFIG)
    host = file.read().strip()
    file.close()
    if removePort and host and len(host) > 0:
        match = matchHost(host)
        if match:
            return match.group('host')
    return host

SSO_HOST_CONFIG = '/etc/vmware-identity/hostname.txt'

class Controller:
    def ssoInfo(self, response, locale, action, input):
        response.addKeyValue('sso.status', '')
        # In case if domain name is not hard coded the action should be 'enable'
        response.addKeyValue('sso.domain', DEFAULT_DOMAIN_NAME, 'disable')
        response.addKeyValue('sso.password1', '', 'enable')
        response.addKeyValue('sso.password2', '', 'enable')
        status = getSsoStatus()
        if isSsoInitialized():
            try:
                response.addKeyValue('sso.status', status)
                response.addKeyValue('sso.domain', getSsoDomain(), 'disable')
                response.addKeyValue('sso.password1', '', 'disable')
                response.addKeyValue('sso.password2', '', 'disable')
                response.setStatus(True, 'SSO is initialized.')
            except Exception, e:
                response.addKeyValue('sso.status', 'ERROR: ' + str(e))
                response.setStatus(False, 'Error getting SSO status.')
        else:
            response.setStatus(False, 'SSO is not initialized.')

    def ssoInit(self, response, locale, action, input):
        if isSsoInitialized():
            self.ssoInfo(response, locale, action, input)
            raise ValueError('SSO is already initialized.')
        domain = vami.requireValue(input.getWidgetValue('sso.domain'))
        password1 = vami.requireValue(input.getWidgetValue('sso.password1'))
        password2 = vami.requireValue(input.getWidgetValue('sso.password2'))
        if password1 != password2:
            raise ValueError('Passwords do not match.')
        vami.callExternalCommand(['/usr/lib/vmware-identity-va-mgmt/firstboot/vmware-identity-va-firstboot.sh',
                                  '--domain',
                                  domain,
                                  '--password',
                                  password1
        ], errorMessage='Error running SSO initialization.')
        # Regenerate SSL certificate with Common Name that match the current host name
        generateCertificate('US', getSsoHost(True), None)
        vami.callExternalCommand(['/etc/init.d/vmware-stsd', 'restart'])
        self.ssoInfo(response, locale, action, input)

    def certificateInfo(self, response, locale, action, input):
        def getCertificateField(data, field):
            for key in data:
                if key:
                    s = key.strip().split('=', 1)
                    if len(s) >= 2 and s[0] == field:
                        return s[1]
            return ''

        def callOpenSSLCustomParam(certificate, arg):
            txt = callOpenSSL(['x509', arg, '-noout'], certificate)
            if txt:
                s = txt.strip().split('=', 1)
                if len(s):
                    return s[1]
            return ''

        fields = [
            'commonName',
            'organization',
            'organizationalUnit',
            'country',
            'serial',
            'key',
            'start',
            'end',
            'encoded.key',
            'encoded.cert',
            'passphrase'
        ]
        response.addKeyValue('ssl.action', '')
        for field in fields:
            response.addKeyValue('ssl.%s' % field, '', 'disable')
        checkIfSsoIsInitialized()
        certificate = callOpenSSL(['pkcs12', '-in', SSL_STORE_FILE, '-nokeys', '-passin', 'pass:%s' % SSL_STORE_PWD])
        if certificate:
            txt = callOpenSSL(['x509', '-subject', '-noout'], certificate)
            if txt:
                data = txt.strip().split('/')
                response.addKeyValue('ssl.commonName', getCertificateField(data, 'CN'), 'disable')
                response.addKeyValue('ssl.organization', getCertificateField(data, 'O'), 'disable')
                response.addKeyValue('ssl.organizationalUnit', getCertificateField(data, 'OU'), 'disable')
                response.addKeyValue('ssl.country', getCertificateField(data, 'C'), 'disable')
            response.addKeyValue('ssl.serial', callOpenSSLCustomParam(certificate, '-serial'), 'disable')
            response.addKeyValue('ssl.key', callOpenSSLCustomParam(certificate, '-fingerprint'), 'disable')
            response.addKeyValue('ssl.start', callOpenSSLCustomParam(certificate, '-startdate'), 'disable')
            response.addKeyValue('ssl.end', callOpenSSLCustomParam(certificate, '-enddate'), 'disable')

    def certificateReplace(self, response, locale, action, input):
        checkIfSsoIsInitialized()
        replaceAction = vami.requireValue(input.getWidgetValue('ssl.action'), 'Please, choose Action!')
        if replaceAction == 'generate':
            cn = input.getWidgetValue('ssl.commonName')
            if cn:
                cn = cn.strip()
            if not len(cn):
                cn = getSsoHost(True)
            org = vami.requireValue(input.getWidgetValue('ssl.organization'))
            orgUnit = vami.requireValue(input.getWidgetValue('ssl.organizationalUnit'))
            country = vami.requireValue(input.getWidgetValue('ssl.country'))
            if len(country) != 2:
                raise ValueError("Country Code should be two letters long.")
            generateCertificate(country, cn, org, orgUnit)
        elif replaceAction == 'import':
            key = vami.requireValue(input.getWidgetValue('ssl.encoded.key'))
            certificate = vami.requireValue(input.getWidgetValue('ssl.encoded.cert'))
            passphrase = input.getWidgetValue('ssl.passphrase')
            importCertificate(certificate, key, passphrase)
        else:
            raise Exception('Unsupported Action Type: %s', replaceAction)
        vami.callExternalCommand(['/etc/init.d/vmware-stsd', 'restart'])
        self.certificateInfo(response, locale, action, input)
        response.setStatus(True, "SSL Certificate is replaced successfully.")

    def hostInfo(self, response, locale, action, input):
        if isSsoInitialized():
            response.addKeyValue('sso.host', getSsoHost())
        else:
            self.ssoInfo(response, locale, action, input)

    def hostUpdate(self, response, locale, action, input):
        if isSsoInitialized():
            host = vami.requireValue(input.getWidgetValue('sso.host'))
            file = open(SSO_HOST_CONFIG, 'w')
            file.write(host)
            file.write('\n')
            file.close()
            self.hostInfo(response, locale, action, input)
        else:
            self.ssoInfo(response, locale, action, input)

    def adInfo(self, response, locale, action, input, status=None):
        checkIfSsoIsInitialized()
        response.addKeyValue('ad.domain', '', 'enable')
        response.addKeyValue('ad.user', '')
        response.addKeyValue('ad.password', '')
        response.addKeyValue('ad.status', '')
        response.addKeyValue('ad.dn', '')
        response.addKeyValue('ad.status1', '')
        response.addKeyValue('ad.status2', '')
        response.addKeyValue('ad.status3', '')
        response.addKeyValue('ad.status4', '')
        response.addKeyValue('ad.status5', '')

        if not isinstance(status, dict):
            status = getActiveDirectoryStatus()
        if 'domain' in status and 'name' in status:
            response.addKeyValue('ad.domain', status['domain'], 'disable')
            response.addKeyValue('ad.status', 'Joined to domain %s' % status['domain'])
            if 'distinguished name' in status:
                response.addKeyValue('ad.dn', status['distinguished name'])
            msgs = checkNetworkSettings(status['domain'])
            if msgs:
                i = 0
                for msg in msgs:
                    i = i + 1
                    response.addKeyValue('ad.status%s' % i, msg)
                if i > 0:
                    i = i + 1
                    if i > 5: i = 5
                    response.addKeyValue('ad.status%s' % i,
                        "There is a network misconfiguration. Check the host name, DNS Servers, and DHCP settings on the Network tab. You may need to restart the appliance after changing the network configuration.")

        else:
            message = 'Not joined to any Active Directory domain.'
            response.addKeyValue('ad.status', message)
            response.setStatus(True, message)

    def adJoin(self, response, locale, action, input):
        checkIfSsoIsInitialized()
        status = getActiveDirectoryStatus()
        if 'domain' in status:
            self.adInfo(response, locale, action, input, status)
            response.setStatus(False, 'Already joined to %s' % status['domain'])
        else:
            message = 'Please, fill in all fields.'
            domain = vami.requireValue(input.getWidgetValue('ad.domain'), message)
            user = vami.requireValue(input.getWidgetValue('ad.user'), message)
            password = vami.requireValue(input.getWidgetValue('ad.password'), message)
            callDomainJoin(['join', domain, user, password])
            self.adInfo(response, locale, action, input)

    def adLeave(self, response, locale, action, input):
        checkIfSsoIsInitialized()
        status = getActiveDirectoryStatus()
        if 'domain' in status and 'name' in status:
            message = 'Please, provide valid user credentials.'
            user = vami.requireValue(input.getWidgetValue('ad.user'), message)
            password = vami.requireValue(input.getWidgetValue('ad.password'), message)
            callDomainJoin(['leave', user, password])
            response.setStatus(True, 'Successfully left domain %s' % status['domain'])
        else:
            response.setStatus(False, 'Not joined to any Active Directory domain.')
        self.adInfo(response, locale, action, input)

vami.execute(Controller())
