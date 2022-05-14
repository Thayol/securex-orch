from ctypes import windll
from os.path import exists
import requests
from requests.auth import HTTPBasicAuth
import json
import socket
import base64
import hashlib

def get_drives():
	drives = []
	bitmask = windll.kernel32.GetLogicalDrives()
	letter = ord('A')
	while bitmask > 0:
		if bitmask & 1:
			drives.append(chr(letter) + ':\\')
		bitmask >>= 1
		letter += 1

	return drives

def read_lines(filename):
	fileObj = open(filename, "r")
	lines = fileObj.read().splitlines()
	fileObj.close()
	
	return lines

def sha256sum(filename):
    h  = hashlib.sha256()
    b  = bytearray(128*1024)
    mv = memoryview(b)
    with open(filename, 'rb', buffering=0) as f:
        for n in iter(lambda : f.readinto(mv), 0):
            h.update(mv[:n])
    return h.hexdigest()

f = open("guid.txt", "r")
guid = f.read()
f.close()

drives = get_drives()
drives.remove('C:\\')

malicious_drives = []

for drive in drives:
	letter = drive.replace(':\\', '')
	path = drive + 'autorun.inf'
	if exists(path):
		malicious = False
		malicious_file = ""
		lines = read_lines(path)
		for line in lines:
			if line.find("open") >= 0:
				malicious = True
			elif line.find("shellexecute") >= 0:
				malicious = True
			
			if malicious:
				malicious_file = line.split('=')[1]
				filehash = sha256sum(drive + malicious_file)
				break
		
		if malicious:
			malicious_drives.append({ "letter": letter, "drive": drive, "contents": lines, "file": malicious_file, "hash": filehash })
			print('MALICIOUS AUTORUN WAS FOUND ON ' + drive)
			print(malicious_drives[-1])

if len(malicious_drives) > 0:
    r = requests.post('https://visibility.amp.cisco.com/iroh/oauth2/token', data={'grant_type': 'client_credentials'},auth=HTTPBasicAuth('$ANONIMIZED_CLIENT_ID', '$ANONIMIZED_TOKEN'))

    response_json = json.loads(r.text)

    token = "UNDEFINED"
    if "access_token" in response_json:
        token = response_json["access_token"]

    if token != "UNDEFINED":
        print("Token found. Request made.")
        hostname = socket.gethostname()
        report = {"guid": guid, "host": hostname, "drives": malicious_drives}
        message = json.dumps(report)
        message_bytes = message.encode('ascii')
        base64_bytes = base64.b64encode(message_bytes)
        base64_message = base64_bytes.decode('ascii')
        observable_type = "url"
        observable_value = base64_message
        r = requests.post('https://visibility.amp.cisco.com/iroh/iroh-response/respond/trigger/e92ecd70-345f-4091-9407-3f41d60fe580/01SDM5XVWC0AO6OI34rd2LE9TvZzKzHTIYV?observable_type=' + observable_type + '&observable_value=' + observable_value + '&workflow_id=01SDM5XVWC0AO6OI34rd2LE9TvZzKzHTIYV', headers={'Authorization': 'Bearer ' + token})
        print(r.text)
else:
    print("No autoruns found.")
