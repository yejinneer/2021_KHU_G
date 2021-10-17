from googleapiclient.discovery import build
from httplib2 import Http
from oauth2client import file, client, tools

from pathlib import Path
import os
BASE_DIR = Path(__file__).resolve().parent.parent

LOG_FOLDER_DIR= os.path.join(os.getcwd(), 'myproject/logs') 
LOG_FILE = os.path.join(os.getcwd(), 'myproject/logs') + "/log.txt"
HASH_FILE = os.path.join(os.getcwd(), 'myproject/logs') + "/hash.txt"

print(LOG_FOLDER_DIR)

#로그파일 짤라서 저장
LOG_FILE_CNT = 0
with open(LOG_FILE, 'r') as txt:
    a = txt.readlines()
    LOG_FILE_CNT = int(len(a)/500)
for i in range(int(len(a)/500)):
    b = i+1
    with open(f'log-{b}.txt', 'w+') as txt:
        tmptxt = ""
        for j in range(500):
            tmptxt += a[j + i*500]
        txt.write(tmptxt)

#해시파일 짤라서 저장
HASH_FILE_CNT = 0
with open(HASH_FILE, 'r') as txt:
    a = txt.readlines()
    HASH_FILE_CNT = int(len(a)/10)
for i in range(int(len(a)/10)):
    b = i+1
    with open(f'hash-{b}.txt', 'w+') as txt:
        tmptxt = ""
        for j in range(10):
            tmptxt += a[j + i*10]
        txt.write(tmptxt)

try :
    import argparse
    flags = argparse.ArgumentParser(parents=[tools.argparser]).parse_args()
except ImportError:
    flags = None

SCOPES = 'https://www.googleapis.com/auth/drive.file'
store = file.Storage('storage.json')
creds = store.get()

G_CLIENT = os.path.join(BASE_DIR)+ "g_client_key.json"

if not creds or creds.invalid:
    print("make new storage data file ")
    flow = client.flow_from_clientsecrets(G_CLIENT, SCOPES)
    creds = tools.run_flow(flow, store, flags) if flags else tools.run(flow, store)

DRIVE = build('drive', 'v3', http=creds.authorize(Http()))

log_folder_id = '1M67z01odYWElrIEmr2oxpMclft0D_av5'
hash_folder_id = '1ZRSFmKXcJqIkTbTLI6KfM7qUJwVY21xm'

#로그파일 이름 불러오기
LOG_FILE_LIST = []
for i in range(LOG_FILE_CNT):
    b = i+1
    LOG_FILE_LIST.append('log-'+str(b)+'.txt')

HASH_FILE_LIST = []
for i in range(HASH_FILE_CNT):
    b = i+1
    HASH_FILE_LIST.append('hash-'+str(b)+'.txt')


for file_title in LOG_FILE_LIST :
    file_name = file_title
    metadata = {'name': file_name,
                'parents' : [log_folder_id],
                'mimeType': None
                }

    res = DRIVE.files().create(body=metadata, media_body=file_name).execute()
    if res:
        print('Uploaded "%s" (%s)' % (file_name, res['mimeType']))

for file_title in HASH_FILE_LIST :
    file_name = file_title
    metadata = {'name': file_name,
                'parents' : [hash_folder_id],
                'mimeType': None
                }

    res = DRIVE.files().create(body=metadata, media_body=file_name).execute()
    if res:
        print('Uploaded "%s" (%s)' % (file_name, res['mimeType']))