# PhishGuard



PhishGuard is a hybrid AI-powered phishing detection system that analyzes URLs to identify potential security threats. It combines machine learning, neural networks, and rule-based analysis to provide accurate and explainable results.



## Features



- Hybrid detection using machine learning and neural networks

- URL feature extraction and analysis

- Brand impersonation detection

- Risk classification (Safe, Suspicious, Phishing)

- Threat score visualization

- Indicators and actionable recommendations



## How It Works



PhishGuard processes a URL by extracting structural and lexical features. These features are passed through both a traditional machine learning model and a neural network. The outputs are combined to produce a final threat score.


Additional rule-based checks are applied to detect suspicious patterns and possible brand impersonation. The system then presents a classification along with supporting indicators and recommendations.



## Project Structure



PhishGuard/

│

├── app.py

├── model.pkl

├── nn_model.pkl

├── templates/

│   └── index.html

├── train_model.py

├── train_nn_model.py

├── requirements.txt

└── README.md



## Running the Application



python app.py



Open your browser and navigate to:

http://127.0.0.1:5000/



## Usage



Enter a URL into the input field and click "Scan". The system will return:



- Classification (Safe, Suspicious, Phishing)

- Threat score

- Risk level

- Indicators

- Recommendations



## Notes



- The system is calibrated to prioritize security, meaning borderline cases may be classified as phishing.

- Model performance is dependent on the quality of the trained dataset.



## Author



Oluwatosin Deborah Ajinomisan  

GitHub: https://github.com/ajinotosin-cyber
