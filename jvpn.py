#!/usr/bin/env python

from __future__ import print_function

import sys
import os
import re
import subprocess
import getpass
import urllib
import http.cookiejar
import ssl
import argparse
import time
import signal
from contextlib import closing

try:
  import gzip
except:
  gzip = None
try:
  import zlib
except:
  zlib = None


def exit_with_error(msg):
  print(msg, file=sys.stderr)
  sys.exit(1)


def fetch(opener, cookies, url, data = None):
  req = urllib.request.Request(url)
  if gzip and zlib:
    req.add_header("Accept-encoding", "gzip, deflate")
  elif gzip:
    req.add_header("Accept-encoding", "gzip")
  elif zlib:
    req.add_header("Accept-encoding", "deflate")
  
  if data:
    data = data.encode("utf-8")

  with closing(opener.open(req, data)) as f:

    if gzip and f.getheader("content-encoding") == "gzip":
      with gzip.GzipFile(fileobj=f) as ff:
        data = ff.read()
    elif zlib and f.getheader("content-encoding") == "deflate":
      data = zlib.decompress(f.read(), -zlib.MAX_WBITS)
    else:
      data = f.read()

    cookies.save()
    return data.decode("utf-8")


def get_stats():
  iface = "tun0"
  device = iface + ":"
  for line in open("/proc/net/dev"):
    data = [x for x in line.split(" ") if x]
    if data[0] == device:
      return (data[1], data[2], data[9], data[10])
  return None


def main():
  p = argparse.ArgumentParser(description="Connects to Juniper VPN.")
  p.add_argument("-c", dest="host", action="store", help="VPN site to connect")
  p.add_argument("-u", dest="user", action="store", help="username for login")
  p.add_argument("-s", dest="stop", action="store_true", help="stops VPN connection")
  p.add_argument("-i", dest="info", action="store_true", help="display info about current state")

  args = p.parse_args()

  home = os.path.join(os.getenv("HOME"), ".juniper_networks")
  if not os.path.isdir(home):
    exit_with_error("Juniper VPN not found in '%s'" % home)
 
  cache = os.path.join(home, "cache")
  if not os.path.isdir(cache):
    os.mkdir(cache)

  ncui = os.path.join(home, "network_connect", "ncui")
  if not os.path.exists(ncui):
    exit_with_error("ncui binary does not exist")

  try:
    pid = subprocess.check_output(["pidof", "ncsvc"])
  except subprocess.CalledProcessError:
    pid = None

  if args.info:
    if pid is None:
      print("VPN is not running")
    else:
      print("VPN is running")
      stats = get_stats()
      if stats is None:
        exit_with_error("no VPN interface found")
      print("Received bytes    = %s" % stats[0])
      print("Transmitted bytes = %s" % stats[2])
    return

  if args.host is None:
    exit_with_error("please specify host")

  base = "https://%s/dana-na/auth/url_default/" % args.host

  cookies_file = os.path.join(cache, args.host + ".cookies")
  cookies = http.cookiejar.MozillaCookieJar(cookies_file, delayload=True)
  opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookies))

  if os.path.isfile(cookies_file):
    cookies.load()

  if args.stop:
    if pid is None:
      exit_with_error("VPN is not currently running")
    else:

      print("Logging out from VPN... ", end="", flush=True)
      fetch(opener, cookies, base + "logout.cgi")
      print("OK", flush=True)

      print("Closing VPN connection... ", end="", flush=True)
      subprocess.check_output([os.path.join(home, "network_connect", "ncsvc"), "-K"])
      print("OK", flush=True)

      return

  if pid is not None:
    exit_with_error("VPN is already running")

  if args.user is None:
    exit_with_error("please specify username")

  der = os.path.join(cache, args.host + ".der")
  if not os.path.isfile(der):
    print("Getting '%s' certificate... " % args.host, end="", flush=True)

    pem = ssl.get_server_certificate((args.host, 443))
    with open(der, "wb") as fh:
      fh.write(ssl.PEM_cert_to_DER_cert(pem))

    print("OK", flush=True)

  password = getpass.getpass()

  print("Connecting... ", end="", flush=True)
  data = fetch(opener, cookies, base + "welcome.cgi")
  print("OK", flush=True)

  if "Please sign in to begin your secure session." in data:

    realm = re.search(r'<input type="hidden" name="realm" value="([^"]+)">', data).group(1)

    print("Logging in realm '%s'... " % realm, end="", flush=True)

    data = urllib.parse.urlencode({"tz_offset" : "",
                                   "username"  : args.user,
                                   "password"  : password,
                                   "realm"     : realm,
                                   "btnSubmit" : "Sign In"})
    data = fetch(opener, cookies, base + "login.cgi", data)

    if "Invalid username or password." in data:
      exit_with_error("invalid username or password")

    print("OK", flush=True)

  if "You have access to the following roles" in data:

    m = re.search(r'<a href="(login\.cgi\?loginmode=mode_selectedrole&role=[^"]+)">([^<]+)</a>', data)
    url = m.group(1)

    print("Selecting role '%s'... " % m.group(2), end="", flush=True)
    data = fetch(opener, cookies, base + url)
    print("OK", flush=True)

  if "There are already other user sessions in progress" in data:

    print("Session already in progress, overriding... ", end="", flush=True)

    dsid = re.search(r'<input id="DSIDFormDataStr" type="hidden" name="FormDataStr" value="([^"]+)">', data).group(1)

    data = urllib.parse.urlencode({"btnContinue": "Continue the session",
                                   "FormDataStr": dsid})
    data = fetch(opener, cookies, base + "login.cgi", data)

    print("OK", flush=True)

  if "Loading Content..." not in data:
    key = re.search(r'<input type="hidden" name="key" value="([^"]+)">', data)
    if key:
      data = urllib.parse.urlencode({"key" : key.group(1), "btnSubmit" : "Sign In"})
      data = fetch(opener, cookies, base + "login.cgi", data)

  redir = re.search(r"<body onload=\"startFunc\(0, '/dana/home/index\.cgi', '[^']+'\);\">", data)

  if "Loading Content..." not in data and not redir:
    open("dump.html", "w").write(data)
    exit_with_error("Could not login to VPN site")

  cookies.load()

  dsid = None
  for c in cookies:
    if c.name == "DSID":
      dsid = c.value
      break

  if not dsid:
    exit_with_error("Could not find DSID value")
    
  print("Starting VPN connection... ", end="", flush=True)

  p = subprocess.Popen([ncui],
                       shell=False,
                       cwd=os.path.join(home, "network_connect"),
                       stdin=subprocess.PIPE, 
                       preexec_fn=os.setsid)

  data = "\n".join(["./ncui", "-h", args.host, "-f", der, "-c", "DSID=" + dsid, "-p", password]) + "\n"

  p.stdin.write(data.encode("utf-8"))
  p.stdin.close()

  for i in range(10):
    iface = "tun0"
    device = iface + ":"
    for line in open("/proc/net/dev"):
      data = [x for x in line.split(" ") if x]
      if data[0] == device:
        print("OK", flush=True)
        return
    time.sleep(1)

  exit_with_error("Failed to connect to VPN")

if __name__ == "__main__":
  main()
