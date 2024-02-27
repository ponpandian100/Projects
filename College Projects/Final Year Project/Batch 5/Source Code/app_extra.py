import joblib
import numpy as np
import pickle
import warnings
warnings.filterwarnings('ignore')
from inputScript import FeatureExtraction
model2 = pickle.load(open('Phishing_website.pkl', 'rb'))
from sklearn.feature_extraction.text import TfidfVectorizer

model1=joblib.load('mail.pkl')
feature_extraction=joblib.load('feature_extraction.pkl')

from flask import Flask, redirect, url_for, render_template, request
app = Flask(__name__)

@app.route("/")
@app.route("/layout")
def layout():
    return render_template("layout.html")

@app.route("/mail")
def mail():
    return render_template("index.html")

@app.route("/mail_predict", methods=['POST']) 
def mail_predict():
    input_mail=[request.form.get("message")]
    # Convert text to the feature vectors 
    input_data_features = feature_extraction.transform(input_mail)
    # making the prediction
    predictionInput =model1.predict(input_data_features)
    if predictionInput[0] == 1:        
        return render_template("mail.html",prediction_text="It is Ham Message",pred=predictionInput[0],message=message)
    else:
        return render_template("mail.html",prediction_text="It is Spam Message",pred=predictionInput[0],message=message)

#Redirects to the page to give the user input URL
@app.route("/link")
def link():
    return render_template("link.html")

#Fetches the URL given by the user and passes to inputScript
@app.route("/predict", methods=['GET','POST'])
def predict():
    ''' 
    for rendering results on HTML GUI
    '''
    if request.method=='POST':
        url = request.form['url']
        ob = FeatureExtraction(url)
        z = np.array(ob.getFeaturesList()).reshape(1,30)
        y_pred=model2.predict(z)[0]
        c=model2.predict_proba(z)[0,0]
        f=model2.predict_proba(z)[0,1]
        if(y_pred==1):
            return render_template("url.html",prediction_text="It is Legitimate safe website",pred=y_pred,url=url)
        else:
            return render_template("url.html",prediction_text="It is a phishing Website",pred=y_pred,url=url)
        
    else:
        return render_template("url.html")

if __name__=='__main__':
    app.run()
