import json
import os
import sqlite3
import requests
from flask import Flask, redirect, request, url_for, render_template, jsonify, send_file, send_from_directory, safe_join, abort
from werkzeug.utils import secure_filename
from flask import json

from db import init_db_command
from file_model import FileModel
from url_model import UrlModel



app = Flask(__name__)



app.config['FILE_FOLDER'] = 'files'
app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(24)
API_KEY = 'c0dc4a79550ca8e7d1b51f954cb86f3cf46b0fe6cd208d6a431ca6b36ee38696'

# These lines will create database (sqlite3) when we run the app for the first time, which will make 2 tables in the database
try:
    init_db_command()
except sqlite3.OperationalError:
    pass

if not os.path.exists('files'):
    os.makedirs('files')


# Home Route It will display index.html in browser
@app.route("/")
def index():
    return render_template('index.html')


# When User click on Upload File button or Scan File link
@app.route('/file/scan', methods=['GET'])
def upload_file():
    return render_template('file_scan.html')

# When User click on Upload URL button or Scan URL link
@app.route('/url/scan', methods=['GET'])
def upload_url():
    return render_template('url_scan.html')




# When user will upload the file, The file will come to this route, it will upload it VirusTotal API
@app.route('/file/scan', methods=['POST'])
def upload_file_post():
    if request.method == "POST":

        if request.files:
            # get the uploaded file
            uploaded_file = request.files["customFile"]
            filename = secure_filename(uploaded_file.filename)
            print(uploaded_file)
            # save file in files folder
            uploaded_file.save('files/'+filename)
            
            try:
                
                url = 'https://www.virustotal.com/vtapi/v2/file/scan'

                params = {'apikey': API_KEY}

                files = {'file': (filename, open('files/'+filename), 'rb')}

                response = requests.post(url, files=files, params=params)

                print(response.json())
                # Save filename and hash in the database
                if not FileModel.get(response.json()['resource']):
                    FileModel.create(response.json()['resource'], filename, response.json()['resource'])
                # if everything went will file_scan.html will be displayed with message of success
                return render_template('file_scan.html',msg=1)
            except:
                # if everything went wrong file_scan.html will be displayed with message of failure
                return render_template('file_scan.html',msg=0)


# When user will upload the url, The url will come to this route, it will upload it VirusTotal API
@app.route('/url/scan', methods=['POST'])
def upload_url_post():
    if request.method == "POST":

        uploaded_url = request.form["url"]
        print(uploaded_url)
        
        try:
            
            url = 'https://www.virustotal.com/vtapi/v2/url/scan'

            params = {'apikey': API_KEY, 'url':uploaded_url}

            

            response = requests.post(url, params=params)

            print(response.json())
            # Save url and hash in the database
            f = UrlModel(
                id_=response.json()['scan_id'], name=uploaded_url, resource=response.json()['scan_id']
            )

            if not UrlModel.get(response.json()['resource']):
                UrlModel.create(response.json()['scan_id'], uploaded_url, response.json()['scan_id'])
            # if everything went will url_scan.html will be displayed with message of success
            return render_template('url_scan.html',msg=1)
        except:
            # if everything went wrong url_scan.html will be displayed with message of failure
            return render_template('url_scan.html',msg=0)
            


# JSON file Download Path for Files, like http://127.0.0.1:5000/file/download/hash
@app.route("/file/download/<path:id>")
def download_file_report(id):

    # API end point to get json
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': API_KEY, 'resource': id}

    response = requests.get(url, params=params)

    data = response.json()
    # dump the json into report.json file
    with open('files/report.json', 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=4)

    # make a safe path to access file
    safe_path = safe_join(app.config["FILE_FOLDER"], 'report.json')
    print(safe_path)
    try:
        # It will download the file/ send the file to use
        return send_file(safe_path, as_attachment=True)
    except FileNotFoundError:
        # It will run if The file not found
        print('ERROR File not found')
        return safe_path
        abort(404)
    except Exception as e:
        # It will run if there is something else error
        print(e)
        return e

# JSON file Download Path for URLs, like http://127.0.0.1:5000/url/download/hash
@app.route("/url/download/<path:id>")
def download_url_report(id):

    # API end point to get json
    url = 'https://www.virustotal.com/vtapi/v2/url/report'
    params = {'apikey': API_KEY, 'resource': id}

    response = requests.get(url, params=params)

    data = response.json()
    # dump the json into report.json file
    with open('files/report.json', 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=4)
    # make a safe path to access file
    safe_path = safe_join(app.config["FILE_FOLDER"], 'report.json')
    print(safe_path)
    try:
        # It will download the file/ send the file to use
        return send_file(safe_path, as_attachment=True)
    except FileNotFoundError:
        # It will run if The file not found
        print('ERROR File not found')
        return safe_path
        abort(404)
    except Exception as e:
        # It will run if there is something else error
        print(e)
        return e



#  This route will return all data stored in file table of the database in json form, which then passed to DataTables to display to the user
@app.route("/files")
def file_data():
    # fetch all rows
    rows = FileModel.get_all()
    # make json data with id, name and resource(hash) and html buttons to download and view report
    json_data=[]
    for result in rows:
        data = {}
        data['id'] = result['id']
        data['name'] = result['name']
        data['resource'] = result['resource'] 
        data['action'] = '<a href="/file/report/'+result['resource'] +'" class="btn btn-info">View Report</a> <a target="_blank()" href="/file/download/'+result['resource'] +'" class="btn btn-info">Download Report</a>'
        json_data.append(data)
    return json.dumps(json_data)

#  This route will return all data stored in url table of the database in json form, which then passed to DataTables to display to the user
@app.route("/urls")
def url_data():
    # fetch all rows
    rows = UrlModel.get_all()
    # make json data with id, name and resource(hash) and html buttons to download and view report
    json_data=[]
    for result in rows:
        data = {}
        data['id'] = result['id']
        data['name'] = result['name']
        data['resource'] = result['resource'] 
        data['action'] = '<a href="/url/report/'+result['resource'] +'" class="btn btn-info">View Report</a> <a target="_blank()" href="/url/download/'+result['resource'] +'" class="btn btn-info">Download Report</a>'
        json_data.append(data)
    return json.dumps(json_data)

# This route will display report of a File based on hash
@app.route('/file/report/<path:filename>')
def file_report(filename):
    # Api end point
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': API_KEY, 'resource': filename}

    response = requests.get(url, params=params)

    data = response.json()
    print(data)
    # trim json, which will then be passed to DataTables to display in a table
    try:
        return_data = []
        count = 0 # It will be the number for which the file is detected to be harmful
        for scan in data['scans']:
            result = data['scans'][scan]['detected'] # True mean file is harmful
            if result == True:
                icon = "<img src='https://img.icons8.com/cute-clipart/64/000000/close-window.png'> Not Clean"
                count -= -1
            else:
                icon = "<img src='https://img.icons8.com/cute-clipart/64/000000/checked-checkbox.png'> Clean"
            return_data.append({'Anti-Virus Engine': scan, 'result' : icon})
            # + str()
        # return_data = json.dumps(return_data)
        return render_template('file_report.html',data=return_data,total=len(return_data),detected=count,precent=(int(count/len(return_data)*100)))
    except:
        return render_template('file_scan.html',msg=3)

# This route will display report of a URL based on hash
@app.route('/url/report/<path:url_>')
def url_report(url_):
    # Api end point
    url = 'https://www.virustotal.com/vtapi/v2/url/report'
    params = {'apikey': API_KEY, 'resource': url_}

    response = requests.get(url, params=params)

    data = response.json()
    print(data)
    # trim json, which will then be passed to DataTables to display in a table
    return_data = []
    count = 0 # It will be the number for which the url is detected to be harmful
    for scan in data['scans']:
        result = data['scans'][scan]['detected'] # True mean url is harmful
        if result == True:
            icon = "<img src='https://img.icons8.com/cute-clipart/64/000000/close-window.png'> Not Clean"
            count -= -1
        else:
            icon = "<img src='https://img.icons8.com/cute-clipart/64/000000/checked-checkbox.png'> Clean"
        return_data.append({'Anti-Virus Engine': scan, 'result' : icon})
        # + str()
    # return_data = json.dumps(return_data)
    return render_template('file_report.html',data=return_data,total=len(return_data),detected=count,precent=(int(count/len(return_data)*100)))



if __name__ == "__main__":
    app.run(debug=True)