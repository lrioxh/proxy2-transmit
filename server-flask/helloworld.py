import os
from functools import wraps
from flask import Flask,send_file,render_template,request
app = Flask(__name__,template_folder="templates")
app.config['UPLOAD_FOLDER'] = 'file_archive'

access_counts = {}

def count_access(route_func):
    @wraps(route_func)
    def wrapper(*args, **kwargs):
        route_name = route_func.__name__
        if route_name not in access_counts:
            access_counts[route_name] = 0
        access_counts[route_name] += 1
        return route_func(*args, **kwargs)
    return wrapper

@app.route('/')
@count_access
def hello_world():
    # global count
    # count+=1
    # print(count)
    # return f"({count})Hello, World!"
    uploaded_files = os.listdir(app.config['UPLOAD_FOLDER'])
    return render_template('homepage.html',count=access_counts, upload_result="", uploaded_files=uploaded_files)
    # return render_template("homepage.html",count=count)

@app.route('/download/',defaults={"selected_file":"test.jpg"})
@count_access
def download(selected_file:str):
    # path=os.path.abspath(r'./file_archive')
    # isShown=selected_file.split('.')[-1]not in ['jpg','pdf']
    filename = os.path.join(app.config['UPLOAD_FOLDER'], selected_file)
    return send_file(filename,as_attachment=False)

@app.route('/download', methods=['POST'])
@count_access
def download_file():
    selected_file = request.form['selected_file']
    filename = os.path.join(app.config['UPLOAD_FOLDER'], selected_file)
    # isShown=selected_file.split('.')[-1]not in ['jpg','pdf']
    # print(selected_file,isShown)
    return send_file(filename, as_attachment=False)

@app.route('/upload', methods=['POST'])
@count_access
def upload_file():
    if 'file' not in request.files:
        return "No file part"
    file = request.files['file']
    if file.filename == '':
        return "No selected file"
    if file:
        filename = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(filename)
        upload_result = "File uploaded successfully"  # Set the upload result
        
        uploaded_files = os.listdir(app.config['UPLOAD_FOLDER'])
        return render_template('homepage.html',count=access_counts, upload_result="", uploaded_files=uploaded_files)
        # return render_template(r"homepage.html",count=count, upload_result=upload_result)
    
if __name__=="__main__":
    app.run("0.0.0.0",4321,True)