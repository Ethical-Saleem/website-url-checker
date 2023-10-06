from flask import Flask, render_template, request, url_for

import FeatureExtraction
import pickle

app = Flask(__name__, static_folder='static')

@app.route('/')
def index():
    # image_url = url_for('static', filename='images/UNILORIN_logo.png')
    return render_template("home.html")

@app.route('/about')
def about():
    return render_template("about.html")

# @app.route('/images/<filename>')
# def get_image(filename):
#     return send_from_directory('static/images', filename)

@app.route('/getURL',methods=['GET','POST'])
def getURL():
    if request.method == 'POST':
        url = request.form['url']
        print(url)
        data = FeatureExtraction.getAttributes(url)
        print(data)
        data.to_csv('RandomData.csv', index=False)
        rf_model = pickle.load(open('RandomForest.sav', 'rb'))
        predicted_value = rf_model.predict(data)
        predicted = predicted_value
        print(predicted)
        #print(predicted_value)
        if predicted_value == 0:    
            value = "This is a legitimate URL"
            # image_url = url_for('static', filename='images/UNILORIN_logo.png')
            return render_template("home.html", error=value)
        else:
            value = "This URL is suspected to be a phishing URL"
            # image_url = url_for('static', filename='images/UNILORIN_logo.png')
            return render_template("home.html", error=value)
if __name__ == "__main__":
    app.run(debug=True)