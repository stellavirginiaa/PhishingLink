import streamlit as st
import pickle
import numpy as np
import pandas as pd
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier

# Function Definitions
def sigmoid_func(x):
    hit = 1 / (1 + np.exp(-x))
    return hit

def calculate_url_length(url):
    '''Function to calculate the total length of the URL link'''
    return len(url)

def calculate_www(url):
    host_len = urlparse(url).hostname
    host_www = 1 if host_len and 'www' in host_len.lower() else 0
    return host_www

def calculate_com(url):
    host_len = urlparse(url).hostname
    host_com = 1 if host_len and '.com' in host_len.lower() else 0
    return host_com

def calculate_dot(url):
    host_len = urlparse(url).hostname
    if host_len:
        host_dot = host_len.lower().count('.')
        return host_dot
    else:
        return 0

def calculate_slash(url):
    path = urlparse(url).path
    slash_count = path.count('/')
    return slash_count

def count_digits(url):
    digit_count = sum(char.isdigit() for char in url)
    return digit_count

def calculate_hostname_length(url):
    parsed_url = urlparse(url)
    return len(parsed_url.netloc)

def calculate_ratio_digits(string):
    if len(string) == 0:
        return 0
    digit_count = sum(char.isdigit() for char in string)
    return digit_count / len(string)

# Load the trained model
with open('random_forest_model.pkl', 'rb') as model:
    loaded_model = pickle.load(model)

# Streamlit App
def introduction():
    st.write("""
    # Phishing Link Detector
    
    Phishing is a fraudulent practice where attackers attempt to obtain sensitive information such as passwords, credit card data, or other financial information by masquerading as a trustworthy entity in electronic communication. Phishing attacks often occur via email, text messages, or fake websites.
    
    Security awareness in identifying phishing links is crucial to protect oneself and personal information from cyber attacks. With this tool, you can check the security of a URL to see if it is safe or suspicious.
    
    Please enter the URL you want to check and click the 'Detect' button to see the results.
    """)

def main():
    introduction()
    
    # User input for the URL
    url = st.text_input("Enter the URL:")

    if st.button("Detect Phishing"):
        # Extract features from the URL
        features = {
            'nb_www': calculate_www(url),
            'nb_com': calculate_com(url),
            'length_dot': calculate_dot(url),
            'length_slash': calculate_slash(url),
            'length_digits': count_digits(url),
            'length_url': calculate_url_length(url),
            'length_hostname': calculate_hostname_length(url),
            'ratio_digits_url': calculate_ratio_digits(url),
            'ratio_digits_host': calculate_ratio_digits(urlparse(url).netloc)
        }

        new_data = pd.DataFrame([features])

        # Predict using the RandomForestClassifier model
        try:
            prediction = loaded_model.predict(new_data)
            st.write("Predictions:")
            output_result(prediction[0], url)

            st.write("Feature Information:")
            st.dataframe(new_data)  # Display the feature information
        except Exception as e:
            st.error(f"Error occurred: {e}")

def output_result(prediction, url):
    if prediction == 0:
        st.write(f'The URL {url} is a legitimate link')
    elif prediction == 1:
        st.write('The entered URL is a phishing link')

if __name__ == "__main__":
    main()
