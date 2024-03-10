# api.py
import json
from datetime import datetime
import requests
from requests_toolbelt.multipart.encoder import MultipartEncoder

SERVER = "http://127.0.0.1:8000"
APIKEY = '6d8053475b8d0f41f0ce88f734291607d663cc5d0c4b233b61d0f30138616ab4'


#정적분석 api
def upload(file_path):
    """Upload File"""
    print("Uploading file")
    multipart_data = MultipartEncoder(fields={'file': (file_path, open(file_path, 'rb'), 'application/octet-stream')})
    headers = {'Content-Type': multipart_data.content_type, 'Authorization': APIKEY}
    response = requests.post(SERVER + '/api/v1/upload', data=multipart_data, headers=headers)

    if response.json().get('hash'):
        print('Upload : ', response.text)
        return response
    else:
        print("Upload failed")
        return None

def scan(data):
    print("Scanning file")
    post_dict = json.loads(data)
    headers = {'Authorization': APIKEY}
    response = requests.post(SERVER + '/api/v1/scan', data=post_dict, headers=headers)
    print('Scan : ', response.text)
    return response

def pdf(data):
    print("Generate PDF report")
    headers = {'Authorization': APIKEY}
    data = {"hash": data}
    response = requests.post(SERVER + '/api/v1/download_pdf', data=data, headers=headers, stream=True)
    with open("report.pdf", 'wb') as f:
        for chunk in response.iter_content(chunk_size=1024):
            if chunk:
                f.write(chunk)
    print("Report saved as report.pdf")

def json_resp(data):
    print("Generate JSON report")
    headers = {'Authorization': APIKEY}
    data = {"hash": json.loads(data)["hash"]}
    response = requests.post(SERVER + '/api/v1/report_json', data=data, headers=headers)


def delete(data):
    print("Deleting Scan")
    headers = {'Authorization': APIKEY}
    data = {"hash": data}
    response = requests.post(SERVER + '/api/v1/delete_scan', data=data, headers=headers)





#동적분석 api
def dynamic_analysis_setting(scan_hash):
    if not scan_hash:
        print("No file uploaded or hash not found")
        return
    headers = {'Authorization': APIKEY}
    data = {'hash': scan_hash}
    response = requests.post(f'{SERVER}/api/v1/dynamic/start_analysis', data=data, headers=headers)
    response_json = response.json()
    print('dynamic analysis setting : ', response.text)
    return response_json

def dynamic_analysis_stop(scan_hash):
    if not scan_hash:
        print("No file uploaded or hash not found")
        return
    headers = {'Authorization': APIKEY}
    data = {'hash': scan_hash}
    response = requests.post(f'{SERVER}/api/v1/dynamic/stop_analysis', data=data, headers=headers)
    print("Dynamic Analysis Stop: ", response.text)

def dynamic_analysis_activity_test(scan_hash, activity_type):
    if not scan_hash:
        print("No file uploaded or hash not found")
        return
    headers = {'Authorization': APIKEY}
    data = {'hash': scan_hash, 'test': activity_type}
    response = requests.post(f'{SERVER}/api/v1/android/activity', data=data, headers=headers)
    if response.status_code == 200:
        print("Dynamic Analysis Activity Tester: Success")
    else:
        print("Dynamic Analysis Activity Tester: Failed")

def dynamic_ttl_ssl_test(scan_hash):
    if not scan_hash:
        print("No file uploaded or hash not found")
        return
    headers = {'Authorization': APIKEY}
    data = {'hash': scan_hash}
    response = requests.post(f'{SERVER}/api/v1/android/tls_tests', data=data, headers=headers)
    print("Dynamic analysis TLS/SSL Security Tester: ", response.text)

def frida_instrument(scan_hash, default_hooks=True, auxiliary_hooks='', frida_code='', class_name=None, class_search=None, class_trace=None):
    """Perform Frida Instrumentation"""
    if not scan_hash:
        print("No file uploaded or hash not found for Frida Instrumentation")
        return
    
    headers = {'Authorization': APIKEY}

    data = {
        'hash': scan_hash,
        'default_hooks': default_hooks,
        'auxiliary_hooks': auxiliary_hooks,
        'frida_code': frida_code
    }

    if class_name is not None:
        data['class_name'] = class_name
    if class_search is not None:
        data['class_search'] = class_search
    if class_trace is not None:
        data['class_trace'] = class_trace

    response = requests.post(f'{SERVER}/api/v1/frida/instrument', headers=headers, data=data)
    print("Perform Frida Instrumentation : ", response.text)

def touch(x, y) :
    headers = {'Authorization': APIKEY}
    data = {'x': x, 'y': y}
    response = requests.post(f'{SERVER}/api/v1/dynamic/touch', data=data, headers=headers)
    print('Touch : ', response.text)