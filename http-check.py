#!/usr/bin python

#    __  __________________        ________  ________________ __
#   / / / /_  __/_  __/ __ \      / ____/ / / / ____/ ____/ //_/
#  / /_/ / / /   / / / /_/ /_____/ /   / /_/ / __/ / /   / ,<
# / __  / / /   / / / ____/_____/ /___/ __  / /___/ /___/ /| |
#/_/ /_/ /_/   /_/ /_/          \____/_/ /_/_____/\____/_/ |_|
#
# description:  http header vulnerability analysis project
# github:       https://github.com/phra/http-check
# forked from:  https://github.com/httphacker/gethead
# version:      0.2

import sys
import urllib3
import ssl
import re
http = urllib3.PoolManager()

ssl._create_default_https_context = ssl._create_unverified_context

BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE = range(8)

def has_colours(stream):
    if not hasattr(stream, "isatty"):
        return False
    if not stream.isatty():
        return False
    try:
        import curses
        curses.setupterm()
        return curses.tigetnum("colors") > 2
    except:
        return False
has_colours = has_colours(sys.stdout)

def printout(text, colour=WHITE):
        if has_colours:
                seq = "\x1b[1;%dm" % (30+colour) + text + "\x1b[0m"
                sys.stdout.write(seq)
        else:
                sys.stdout.write(text)

if len(sys.argv) < 2:
  printout('Please provide a fully-qualified path!\n', RED)
  printout('Usage: python gethead.py path\n', WHITE)
  printout('Example: python gethead.py http://www.google.com\n\n', WHITE)
  sys.exit()
else:
  response = http.request('GET',sys.argv[1])
  printout('HTTP Header Analysis for ' + sys.argv[1] + ':' + '\n\n', CYAN)








# check x-xss-protection:
if response.getheader('x-xss-protection') and (response.getheader('x-xss-protection').startswith('1; mode=block') or response.getheader('x-xss-protection').startswith('1;mode=block')):
  printout('(X-XSS-Protection) Cross-Site Scripting Protection is enforced. [VALUE: %s]\n\n' % response.getheader('x-xss-protection'), GREEN)
else:
  printout('Vulnerability ', RED)
  printout('- Server does not enforce Cross-Site Scripting Protection.\nThe X-XSS-Protection Header setting is either inadequate or missing.\nClient may be vulnerable to Cross-Site Scripting Attacks. [VALUE: %s]\n\n' % (response.getheader('x-xss-protection') if response.getheader('x-xss-protection') else 'MISSING'), WHITE)

# check x-frame-options:
if response.getheader('x-frame-options') and response.getheader('x-frame-options').lower() in ['deny', 'sameorigin']:
  printout('(X-Frame-Options) Cross-Frame Scripting Protection is enforced. [VALUE: %s]\n\n' % response.getheader('x-frame-options'), GREEN)
else:
  printout('Vulnerability ', RED)
  printout('- Server does not enforce Cross-Frame Scripting Protection.\nThe X-Frame-Options Header setting is either inadequate or missing.\nClient may be vulnerable to Click-Jacking Attacks. [VALUE: %s]\n\n' % (response.getheader('x-frame-options') if response.getheader('x-frame-options') else 'MISSING'), WHITE)

# check x-content-type-options:
if response.getheader('x-content-type-options') == 'nosniff':
  printout('(X-Content-Type-Options) X-Content-Type-Options is enforced. [VALUE: %s]\n\n' % response.getheader('x-content-type-options'), GREEN)
else:
  printout('Vulnerability ', RED)
  printout('- Server does not enforce X-Content-Type-Options.\nThe X-Content-Type-Options Header setting is either inadequate or missing.\nClient may be vulnerable to MIME-Sniffing Attacks. [VALUE: %s]\n\n' % (response.getheader('x-content-type-options') if response.getheader('x-content-type-options') else 'MISSING'), WHITE)

# check strict-transport-security:
if response.getheader('strict-transport-security'):
    val=re.search('.*=([\d]+).*',response.getheader('strict-transport-security')).group(1)
    #print(val)
    if int(val)>2592000:
        printout('(Strict-Transport-Security) HTTP over TLS/SSL is enforced. [VALUE: %s]\n\n' % response.getheader('strict-transport-security'), GREEN)
    else:
        printout('(Strict-Transport-Security) HTTP over TLS/SSL is enforced but The "max-age" directive is too small. The minimum recommended value is 2592000 (30 days. [VALUE: %s]\n\n' % response.getheader('strict-transport-security'), YELLOW)
else:
  printout('Vulnerability ', RED)
  printout('- Server does not enforce HTTP over TLS/SSL Connections.\nThe Strict-Transport-Security Header setting is either inadequate or missing.\nClient may be vulnerable to Session Information Leakage. [VALUE: %s]\n\n' % (response.getheader('strict-transport-security') if response.getheader('strict-transport-security') else 'MISSING'), WHITE)

# check content-security-policy:
if response.getheader('content-security-policy'):
  printout('(Content-Security-Policy) Content Security Policy is enforced. [VALUE: %s]\n\n' % response.getheader('content-security-policy'), GREEN)
else:
  printout('Vulnerability ', RED)
  printout('- Server does not enforce a Content Security Policy.\nThe Content-Security-Policy Header setting is either inadequate or missing.\nClient may be vulnerable to Cross-Site Scripting and Injection Attacks. [VALUE: %s]\n\n' % (response.getheader('content-security-policy') if response.getheader('content-security-policy') else 'MISSING'), WHITE)

# check x-content-security-policy:
if response.getheader('x-content-security-policy'):
  printout('Deprecated ', YELLOW)
  if not response.getheader('content-security-policy'):
    printout('(X-Content-Security-Policy) Content Security Policy is enforced. (SWITCH TO STANDARD HTTP HEADER: \'Content-Security-Policy\')\n\n', WHITE)
  else:
    printout('(X-Content-Security-Policy) Content Security Policy is enforced. (DROP DEPRECATED HEADER: \'X-Content-Security-Policy\')\n\n', WHITE)

# check x-webkit-csp:
if response.getheader('x-webkit-csp'):
  printout('Deprecated ', YELLOW)
  if not response.getheader('content-security-policy'):
    printout('(X-Webkit-CSP) Content Security Policy is enforced. (SWITCH TO STANDARD HTTP HEADER: \'Content-Security-Policy\')\n\n', WHITE)
  else:
    printout('(X-Webkit-CSP) Content Security Policy is enforced. (DROP DEPRECATED HEADER: \'X-Webkit-CSP\')\n\n', WHITE)

# check access-control-allow-origin:
if response.getheader('access-control-allow-origin'):
  printout('(Access-Control-Allow-Origin) Access Control Policies are enforced. [VALUE: %s]\n\n' % response.getheader('access-control-allow-origin'), GREEN)
else:
  printout('Vulnerability ', RED)
  printout('- Server does not enforce an Access Control Policy.\nThe Access-Control-Allow-Origin Header setting is either inadequate or missing.\nClient may be vulnerable to Cross-Domain Scripting Attacks. [VALUE: %s]\n\n' % (response.getheader('access-control-allow-origin') if response.getheader('access-control-allow-origin') else 'MISSING'), WHITE)

# check x-download-options:
if response.getheader('x-download-options') == 'noopen':
  printout('(X-Download-Options) File Download and Open Restriction Policies are enforced. [VALUE: %s]\n\n' % response.getheader('x-download-options'), GREEN)
else:
  printout('Vulnerability ', RED)
  printout('- Server does not enforce a File Download and Open Policy.\nThe X-Download-Options Header setting is either inadequate or missing.\nClient may be vulnerable to Browser File Execution Attacks. [VALUE: %s]\n\n' % (response.getheader('x-download-options') if response.getheader('x-download-options') else 'MISSING'), WHITE)

# check cache-control:
if response.getheader('cache-control') and (response.getheader('cache-control').startswith('private') or response.getheader('cache-control').startswith('no-cache')):
  printout('(Cache-control) Private Caching or No-Cache is enforced. [VALUE: %s]\n\n' % response.getheader('cache-control'), GREEN)
else:
  printout('Vulnerability ', RED)
  printout('- Server does not enforce a Content Caching Policy.\nThe Cache-control Header setting is either inadequate or missing.\nClient may be vulnerable to Content Caching Attacks. [VALUE: %s]\n\n' % (response.getheader('cache-control') if response.getheader('cache-control') else 'MISSING'), WHITE)

# check x-permitted-cross-domain-policies:
if response.getheader('X-Permitted-Cross-Domain-Policies') == 'master-only' or response.getheader('X-Permitted-Cross-Domain-Policies') == 'none':
  printout('(X-Permitted-Cross-Domain-Policies) X-Permitted-Cross-Domain-Policies are enforced. [VALUE: %s]\n\n' % response.getheader('X-Permitted-Cross-Domain-Policies'), GREEN)
else:
  printout('Vulnerability ', RED)
  printout('- Server does not enforce a X-Permitted-Cross-Domain-Policies.\nThe Cross-Domain Meta Policy Header setting is either inadequate or missing.\nClient may be vulnerable to Cross-Protocol-Scripting Attacks. [VALUE: %s]\n\n' % (response.getheader('X-Permitted-Cross-Domain-Policies') if response.getheader('X-Permitted-Cross-Domain-Policies') else 'MISSING'), WHITE)


# check x-permitted-cross-domain-policies:
if response.getheader('X-Permitted-Cross-Domain-Policies') == 'master-only' or response.getheader('X-Permitted-Cross-Domain-Policies') == 'none':
  printout('(X-Permitted-Cross-Domain-Policies) X-Permitted-Cross-Domain-Policies are enforced. [VALUE: %s]\n\n' % response.getheader('X-Permitted-Cross-Domain-Policies'), GREEN)
else:
  printout('Vulnerability ', RED)
  printout('- Server does not enforce a X-Permitted-Cross-Domain-Policies.\nThe Cross-Domain Meta Policy Header setting is either inadequate or missing.\nClient may be vulnerable to Cross-Protocol-Scripting Attacks. [VALUE: %s]\n\n' % (response.getheader('X-Permitted-Cross-Domain-Policies') if response.getheader('X-Permitted-Cross-Domain-Policies') else 'MISSING'), WHITE)


###M anualy add, need to check it

# check Permissions-Policy:
if response.getheader('Permissions-Policy') == 'interest-cohort=()' or response.getheader('Permissions-Policy') == 'none':
  printout('(Permissions-Policy) Permissions-Policy is enforced. [VALUE: %s]\n\n' % response.getheader('Permissions-Policy'), GREEN)
else:
  printout('Vulnerability ', RED)
  printout('- Server does not enforce a Permissions-Policy.\nThe Cross-Domain Meta Policy Header setting is either inadequate or missing.\nClient may be vulnerable to Cross-Protocol-Scripting Attacks. [VALUE: %s]\n\n' % (response.getheader('Permissions-Policy') if response.getheader('Permissions-Policy') else 'MISSING'), WHITE)

# check Referrer-Policy	:
if response.getheader('Referrer-Policy') == 'interest-cohort=()' or response.getheader('Referrer-Policy') == 'none':
  printout('(Referrer-Policy) Referrer-Policy is enforced. [VALUE: %s]\n\n' % response.getheader('Referrer-Policy'), GREEN)
else:
  printout('Vulnerability ', RED)
  printout('- Server does not enforce a Referrer-Policy.\nThe Cross-Domain Meta Policy Header setting is either inadequate or missing.\nClient may be vulnerable to Cross-Protocol-Scripting Attacks. [VALUE: %s]\n\n' % (response.getheader('Referrer-Policy') if response.getheader('Referrer-Policy') else 'MISSING'), WHITE)

