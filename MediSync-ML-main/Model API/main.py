import os
import io
import base64
from typing import List, Tuple

import cv2
import fitz  # PyMuPDF
import joblib
import numpy as np
import pandas as pd
import spacy
import nltk
import easyocr
import keras_ocr
from PIL import Image, ImageDraw, ImageFilter
from keras.models import model_from_json
from sklearn.preprocessing import MultiLabelBinarizer, StandardScaler
from fastapi import FastAPI, File, UploadFile, Form, Query, HTTPException ,Request, BackgroundTasks
from fastapi.responses import JSONResponse, StreamingResponse
from spacy.matcher import PhraseMatcher
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine, OperatorConfig
from fastapi.middleware.cors import CORSMiddleware
import requests
from pydantic import BaseModel
from io import BytesIO
from pdf2image import convert_from_bytes
import logging
import fitz
import pyshark
import threading
from typing import List, Dict
from datetime import datetime
import json
import asyncio
from concurrent.futures import ThreadPoolExecutor
import anyio
import subprocess
import google.generativeai as genai
from IPython.display import Markdown
import textwrap
import torch




captured_data = []
network_interface = '127.0.0.1'

genai.configure(api_key="AIzaSyC126D4ED0w3B4nB8KdgtgSiCHvaQ7Hhms")
gemini_model = genai.GenerativeModel('gemini-1.5-flash')

# Initialize the FastAPI app
app = FastAPI()


origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)


# Download required NLTK data
nltk.download('punkt')
nltk.download('wordnet')


# Initialize OCR and Presidio
reader = easyocr.Reader(['en'])
easyocr_reader = easyocr.Reader(["en"])
pipeline = keras_ocr.pipeline.Pipeline()
analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()



# Load spacy model
current_dir = os.path.dirname(os.path.abspath(__file__))
nlp = spacy.load(os.path.join(current_dir, "Spacy"))


# Load the model and scaler
password_user_anomaly_model = joblib.load('Password_user_anomaly_detection_model.pkl')
password_scaler = joblib.load('password_scaler.pkl')

input_pdf = ""
output_jpg = "img.jpg"

#The code splits the first page of pdf and converts to jpeg
# @app.post("/pdfcoverters")
# def pdf_to_img(pdf_path, output_path):
#     doc = fitz.open(pdf_path)
#     page = doc.load_page(0)
#     pix = page.get_pixmap()
#     pix.save(output_path, "jpeg")
#     doc.close()


logging.basicConfig(level=logging.DEBUG)
executor = ThreadPoolExecutor()
# Function to capture packets and extract fields
tshark_path = 'C:\\Users\\Saleem Malik\\Downloads\\WiresharkPortable64\\App\\Wireshark\\tshark.exe'

# Initialize the ThreadPoolExecutor


# Load the model




# List to store captured packets
captured_packets = []

def sync_capture_packets(interface: str, duration: int):
    """Synchronous function to capture packets using tshark"""
    try:
        command = [
            tshark_path,
            '-i', interface,
            '-a', f'duration:{duration}',
            # '-Y', 'http and ip.dst == 127.0.0.1',  # Correct filter without quotes around IP address
            '-T', 'json'
        ]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        stdout, stderr = process.communicate()
        
        if process.returncode != 0:
            raise Exception(f'tshark error: {stderr.decode().strip()}')
        
        return json.loads(stdout)
    except Exception as e:
        logging.error(f"Error capturing packets: {e}")
        raise

async def capture_packets(interface: str, duration: int):
    """Asynchronous wrapper for capturing packets"""
    loop = asyncio.get_event_loop()
    capture_result = await loop.run_in_executor(executor, sync_capture_packets, interface, duration)
    return capture_result


async def process_packets(interface: str, duration: int):
    """Function to handle packet capturing and processing"""
    try:
        capture_result = await capture_packets(interface, duration)
        global captured_packets
        captured_packets.clear()  # Clear old packets

        for packet in capture_result:
            layers = packet.get('_source', {}).get('layers', {})
            #print(layers)

            ip_data = layers.get('ip', {})
            tcp_data = layers.get('tcp', {})
            frame_data = layers.get('frame', {})
            # Access fields with default values if not present
            src_ip = ip_data.get('ip.src')
            dst_ip = ip_data.get('ip.dst')
            sport = tcp_data.get('tcp.srcport')
            dport = tcp_data.get('tcp.dstport')

            # Filter out packets with IP 127.0.0.1
            if src_ip == '127.0.0.1' or dst_ip == '127.0.0.1':
                continue

            packet_data = {
                'srcip': src_ip,
                'sport': int(sport) if sport else 0,
                'dstip': dst_ip,
                'dsport': int(dport) if dport else 0,
                'proto': ip_data.get('ip.proto'),
                'state': tcp_data.get('tcp.flags_tree', {}).get('tcp.flags.str'),  # Change as your requirement ######################
                'dur': float(frame_data.get('frame.time_delta', 0)),
                'sbytes': int(frame_data.get('frame.len', 0)),
                'dbytes': None,  # Requires more specific processing
                'sttl': int(ip_data.get('ip.ttl', 0)),
                'dttl': None,  # Requires more specific processing
                'sloss': None,  # Requires calculation
                'dloss': None,  # Requires calculation
                'service': frame_data.get('frame.protocols'),  # This value changed to protocol ##########################
                'Sload': None,  # Requires calculation
                'Dload': None,  # Requires calculation
                'Spkts': None,  # Requires calculation
                'Dpkts': None,  # Requires calculation
                'swin': int(tcp_data.get('tcp.window_size_value', 0)),
                'dwin': None,  # Requires more specific processing
                'stcpb': int(tcp_data.get('tcp.seq', 0)),
                'dtcpb': None,  # Requires more specific processing
                'smeansz': None,  # Requires calculation
                'dmeansz': None,  # Requires calculation
                'trans_depth': None,  # Requires parsing
                'res_bdy_len': None,  # Requires parsing
                'Sjit': None,  # Requires calculation
                'Djit': None,  # Requires calculation
                'Stime': float(frame_data.get('frame.time_epoch', 0)),  # This value changed to frame time #####################
                'Ltime': None,  # Requires specific calculation
                'Sintpkt': None,  # Requires calculation
                'Dintpkt': None,  # Requires calculation
                'tcprtt': None,  # Requires calculation
                'synack': None,  # Requires calculation
                'ackdat': None,  # Requires calculation
                'is_sm_ips_ports': 1 if src_ip == dst_ip and sport == dport else 0,
                'ct_state_ttl': None,  # Requires specific calculation
                'ct_flw_http_mthd': None,  # Requires parsing
                'is_ftp_login': 1 if 'ftp' in (layers.get('service', [None])[0] or '') else 0, # make change this ######################
                'ct_ftp_cmd': None,  # Requires parsing
                'ct_srv_src': None,  # Requires specific calculation
                'ct_srv_dst': None,  # Requires specific calculation
                'ct_dst_ltm': None,  # Requires specific calculation
                'ct_src_ltm': None,  # Requires specific calculation
                'ct_src_dport_ltm': None,  # Requires specific calculation
                'ct_dst_sport_ltm': None,  # Requires specific calculation
                'ct_dst_src_ltm': None,  # Requires specific calculation
                'attack_cat': None,  # Requires classification
                'Label': None  # Requires classification
            }
            captured_packets.append(packet_data)

        # Optionally, write packets to a JSON file
        with open('captured_packets.json', 'w') as f:
            json.dump(captured_packets, f, indent=4)
            print(json.dumps(captured_packets, indent=4))

    except Exception as e:
        logging.error(f"Error processing packets: {e}")


@app.post('/capture')
async def capture_packets_endpoint(
    interface: str = Query(..., description="The network interface to capture packets from"),
    duration: int = Query(..., description="The duration in seconds to capture packets for")
):
    try:
        await process_packets(interface, duration)
        return {"message": "Packet capture started in the background"}
    except Exception as e:
        logging.error(f"Error capturing packets: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")












@app.get("/hide_details_pdf")
async def anonymize_image(request: Request):
    pdf_url = request.query_params.get('pdf_url')
    if not pdf_url:
        raise HTTPException(status_code=400, detail="PDF URL is required")

    try:
        logging.info(f"Received PDF URL: {pdf_url}")

        # Fetch PDF content
        response = requests.get(pdf_url)
        response.raise_for_status()

        if response.headers.get('Content-Type') != 'application/pdf':
            raise HTTPException(status_code=400, detail="The URL does not point to a PDF file")

        pdf_content = response.content
        logging.info("PDF fetched successfully")

        # Convert PDF to image
        image_output = convert_pdf_to_image(pdf_content)
        image_output.seek(0)
        file_content = image_output.getvalue()
        content_type = "image/jpeg"  # Assuming the converted image is in JPEG format

        logging.info(f"File content type: {content_type}")

        all_ocr_results = []
        if content_type.startswith("image/"):
            ocr_results, image = extract_text_from_image(file_content)
            all_ocr_results = [(ocr_results, image)]
        else:
            raise HTTPException(status_code=400, detail="Unsupported file type")

        all_anonymized_images = []
        for ocr_results, image in all_ocr_results:
            extracted_text = " ".join([result[1] for result in ocr_results])

            # Analyze text using Presidio
            analyzer_results = analyzer.analyze(text=extracted_text, language='en')

            # Identify sensitive data locations in the image
            boxes_to_blur = []
            for result in analyzer_results:
                detected_text = extracted_text[result.start:result.end]
                for ocr_result in ocr_results:
                    if detected_text in ocr_result[1]:
                        box = ocr_result[0]
                        boxes_to_blur.append(box)

            # Blur sensitive data in the image
            anonymized_image = blur_image(image, boxes_to_blur)
            all_anonymized_images.append(anonymized_image)

        # Save the anonymized images to a BytesIO object
        output = io.BytesIO()
        if len(all_anonymized_images) == 1:
            all_anonymized_images[0].save(output, format="PNG")
        else:
            all_anonymized_images[0].save(output, format="PDF", save_all=True, append_images=all_anonymized_images[1:])
        output.seek(0)

        return StreamingResponse(output, media_type="application/pdf" if len(all_anonymized_images) > 1 else "image/png")

    except requests.RequestException as e:
        logging.error(f"Error fetching the PDF: {e}")
        raise HTTPException(status_code=400, detail=f"Error fetching the PDF: {e}")
    except Exception as e:
        logging.error(f"Internal server error: {e}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {e}")
# Function to load models and scaler
def load_models_and_scaler():
    try:
        model = joblib.load('One-Class-SVM.pkl')
    except Exception as e:
        raise RuntimeError(f"Error loading the model: {e}")

    try:
        scaler = joblib.load('scaler.pkl')
    except FileNotFoundError:
        scaler = StandardScaler()  # Assuming a new scaler if not found
    except Exception as e:
        raise RuntimeError(f"Error loading the scaler: {e}")

    if not hasattr(scaler, 'mean_'):
        raise RuntimeError("Scaler is not fitted yet. Please fit the scaler on training data and save it.")

    return model, scaler

# Load the models and scaler
loaded_model, scaler = load_models_and_scaler()

# Load seal verification model
with open(os.path.join('model_architecture.json'), 'r') as json_file:
    model_json = json_file.read()

seal_model = model_from_json(model_json)
seal_model.load_weights(os.path.join('Seal_classification_model.h5'))



# Define allowed file extensions
ALLOWED_EXTENSIONS = {'.jpg', '.jpeg', '.png'}

def allowed_file(filename):
    return os.path.splitext(filename)[1].lower() in ALLOWED_EXTENSIONS

# Helper function to convert PIL image to base64 string
def pil_to_base64(pil_img):
    img_byte_array = BytesIO()
    pil_img.save(img_byte_array, format='PNG')
    img_base64 = base64.b64encode(img_byte_array.getvalue()).decode('utf-8')
    return f"data:image/png;base64,{img_base64}"

# Seal verification function
def seal_verification(image_path):
    image = cv2.imread(image_path)
    if image is not None:
        image = cv2.resize(image, (200, 200))
        image = image.astype('float32') / 255.0
        image = cv2.cvtColor(image, cv2.COLOR_BGR2RGB)
        image = np.expand_dims(image, axis=0)
    else:
        return {"error": "Invalid or empty image."}

    predictions = seal_model.predict(image)

    mlb = MultiLabelBinarizer()
    mlb.classes_ = ['No seal', 'seal']

    seal_classe = []
    noseal_classe = []
    score = []

    if len(mlb.classes_) == predictions[0].shape[0]:
        for i in range(len(predictions[0])):
            if predictions[0][i] >= 0.75:
                if mlb.classes_[i] == "seal":
                    seal_classe.append(mlb.classes_[i])
                    score.append(predictions[0][i] * 100)
                else:
                    noseal_classe.append(mlb.classes_[i])
                    score.append(predictions[0][i] * 100)
            else:
                pass
    else:
        return {"error": "Number of classes in mlb.classes_ doesn't match the model's output."}

    if len(seal_classe) != 0:
        return {"text": "Valid seal verification is included in this document", "seal Class": seal_classe[0]}
    else:
        return {"text": "Valid seal verification is not included in this document", "seal Class": "No seal"}
    

# Load spacy model
current_dir = os.path.dirname(os.path.abspath(__file__))
nlp = spacy.load(os.path.join(current_dir, "Spacy"))

def easy_ocr(image_path: str) -> str:
    image = cv2.imread(image_path)
    if image is not None:
        results = easyocr_reader.readtext(image_path)
        all_content = np.array([element[1] for element in results])
        text = " ".join(all_content).capitalize()
        return text
    return ""

def keras_ocr(image_path: str) -> str:
    image = cv2.imread(image_path)
    if image is not None:
        results = pipeline.recognize([image])
        text_df = pd.DataFrame(results[0], columns=['text', 'bbox'])
        text = " ".join(text_df['text']).capitalize()
        return text
    return ""

def score_fun(full_name: str, name_inti: str, address: str, age: str, text: str) -> Tuple[int, int, int]:
    unwanted_symbols = [".", "-", ",", "_", ":-", ":", ";", "%"]
    unwanted_words = ["no-", "no:", "no", ".", ",", "-", "_", ":-", ":", ";", "%", "mawatha", "mawata", "mavatha", "mawata", "mv", "mw", "sri lanka", "sri", "lanka", "para", "road", "rd", "no:-", "no;", "no;", 'handiya', "handhiya"]

    full_name = full_name.lower()
    split_name = full_name.split(" ")

    name_inti = name_inti.lower()
    cleaned_name = ''.join([char for char in name_inti if char not in unwanted_symbols])

    address = address.lower()
    token_addres = nltk.word_tokenize(address)
    address_split = [word for word in token_addres if word not in unwanted_words]

    name_final = []
    address_final = []
    age_final = []

    def full_match(text, variation):
        matcher = PhraseMatcher(nlp.vocab)
        patterns = [nlp(variation)]
        matcher.add("TerminologyList", patterns)
        doc = nlp(text)
        matches = matcher(doc)
        matched = [span.text for _, start, end in matches for span in [doc[start:end]]]
        return 100 if variation in matched else 0

    def split_match(text, variations):
        matcher = PhraseMatcher(nlp.vocab)
        patterns = [nlp(variation) for variation in variations]
        matcher.add("TerminologyList", patterns)
        doc = nlp(text)
        matches = matcher(doc)
        matched = [span.text for _, start, end in matches for span in [doc[start:end]]]
        matched = list(set(matched))
        return len(matched) / len(variations) * 100

    full_name_score = full_match(text, full_name)
    name_inti_score = full_match(text, name_inti)
    cleaned_name_score = full_match(text, cleaned_name)
    split_name_score = split_match(text, split_name)

    address_score = full_match(text, address)
    address_split_score = split_match(text, address_split)

    # Adding age matching (assuming age is provided as a number in string format)
    age_score = 100 if age in text else 0

    name_final.extend([full_name_score, name_inti_score, cleaned_name_score, split_name_score])
    address_final.extend([address_score, address_split_score])
    age_final.append(age_score)

    return max(name_final), max(address_final), max(age_final)

# Load the model and scaler
Password_user_anomaly_detection_model = joblib.load('user_anomaly_detection_model.pkl')
Password_user_anomaly_detection_scaler = joblib.load('user_anomaly_detection_scaler.pkl')

def preprocess_new_data(endpoint_count: int, login_attempts: int, session_duration: int, data_transferred_mb: int):
    df = pd.DataFrame([[endpoint_count, login_attempts, session_duration, data_transferred_mb]])
    scaled_data = Password_user_anomaly_detection_scaler.transform(df)
    return scaled_data

class ImageURL(BaseModel):
    url: str
class ImageURL(BaseModel):
    url: str




# Define the prediction endpoint
@app.get("/user_behaviour_predict")
async def user_behaviour_prediction(
    Login_Frequency: int = Query(...),
    Access_Patient_Info: int = Query(...),
    Time_Spent_On_System: float = Query(...),
    Time_Spent_On_Patient_Records: float = Query(...),
    Actions_Performed: int = Query(...),
    Errors_Encountered: int = Query(...),
    Data_Entries_Added: int = Query(...),
    Data_Entries_Modified: int = Query(...),
    Data_Entries_Viewed: int = Query(...),
    Search_Queries_Performed: int = Query(...),
    Data_Entries_Deleted: int = Query(...),
    Access_Logs_Viewed: int = Query(...),
    Messages_Sent: int = Query(...),
    Messages_Received: int = Query(...)
):
    # Create a DataFrame from the query parameters
    data = pd.DataFrame([{
        'Login_Frequency': Login_Frequency,
        'Access_Patient_Info': Access_Patient_Info,
        'Time_Spent_On_System': Time_Spent_On_System,
        'Time_Spent_On_Patient_Records': Time_Spent_On_Patient_Records,
        'Actions_Performed': Actions_Performed,
        'Errors_Encountered': Errors_Encountered,
        'Data_Entries_Added': Data_Entries_Added,
        'Data_Entries_Modified': Data_Entries_Modified,
        'Data_Entries_Viewed': Data_Entries_Viewed,
        'Search_Queries_Performed': Search_Queries_Performed,
        'Data_Entries_Deleted': Data_Entries_Deleted,
        'Access_Logs_Viewed': Access_Logs_Viewed,
        'Messages_Sent': Messages_Sent,
        'Messages_Received': Messages_Received
    }])
    
    # Preprocess the data
    try:
        data_scaled = scaler.transform(data)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error scaling the data: {e}")
    
    # Predict using the loaded model
    try:
        predictions = loaded_model.predict(data_scaled)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error making predictions: {e}")
    
    # Return the predictions
    return {"predictions": predictions.tolist()}

def extract_text_from_image(file_content):
    # Read image
    image = Image.open(io.BytesIO(file_content))
    # Convert PIL image to NumPy array
    image_np = np.array(image)
    # Perform OCR on the image using EasyOCR
    results = reader.readtext(image_np, paragraph=True)
    return results, image

def extract_text_from_pdf(file_content):
    # Read PDF
    pdf_document = fitz.open(stream=io.BytesIO(file_content), filetype="pdf")
    images = []
    for page_num in range(len(pdf_document)):
        page = pdf_document.load_page(page_num)
        pix = page.get_pixmap()
        pil_image = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
        images.append(pil_image)
    return images

def blur_image(image, boxes):
    for box in boxes:
        left, top, right, bottom = map(int, [min(point[0] for point in box), 
                                            min(point[1] for point in box), 
                                            max(point[0] for point in box), 
                                            max(point[1] for point in box)])
        cropped = image.crop((left, top, right, bottom))
        blurred = cropped.filter(ImageFilter.GaussianBlur(radius=10))
        image.paste(blurred, (left, top))
    return image

# Seal Verification
with open(os.path.join('model_architecture.json'), 'r') as json_file:
    model_json = json_file.read()

seal_model = model_from_json(model_json)
seal_model.load_weights(os.path.join('Seal_classification_model.h5'))

def seal_verification(image_path):
    # Load the test image
    image = cv2.imread(image_path)

    # Preprocess the image
    if image is not None:
        image = cv2.resize(image, (200, 200))
        image = image.astype('float32') / 255.0
        image = cv2.cvtColor(image, cv2.COLOR_BGR2RGB)
        image = np.expand_dims(image, axis=0)
    else:
        return {"error": "Invalid or empty image."}

    # Make predictions
    predictions = seal_model.predict(image)

    mlb = MultiLabelBinarizer()
    mlb.classes_ = ['No seal', 'seal']

    seal_classe = []
    noseal_classe = []
    score = []

    if len(mlb.classes_) == predictions[0].shape[0]:
        for i in range(len(predictions[0])):
            if predictions[0][i] >= 0.75:
                if mlb.classes_[i] == "seal":
                    seal_classe.append(mlb.classes_[i])
                    score.append(predictions[0][i] * 100)
                else:
                    noseal_classe.append(mlb.classes_[i])
                    score.append(predictions[0][i] * 100)
            else:
                pass
    else:
        return {"error": "Number of classes in mlb.classes_ doesn't match the model's output."}

    if len(seal_classe) != 0:
        return {"text": "Valid seal verification is included in this document", "seal Class": seal_classe[0]}
    else:
        return {"text": "Valid seal verification is not included in this document", "seal Class": "No seal"}


@app.get("/convert-image/")
async def convert_image(image_url: ImageURL):
    try:
        # Fetch the image from the URL
        response = requests.get(image_url.url)
        response.raise_for_status()  # Raise an HTTPError for bad responses (4xx and 5xx)

        # Open the image from the response content
        image = Image.open(BytesIO(response.content))

        # Save the image to a BytesIO object
        img_byte_arr = BytesIO()
        image.save(img_byte_arr, format=image.format)
        img_byte_arr.seek(0)

        # Return the image as a StreamingResponse
        return StreamingResponse(img_byte_arr, media_type=f"image/{image.format.lower()}")
    except requests.RequestException as e:
        raise HTTPException(status_code=400, detail=f"Error fetching the image: {e}")
    except IOError as e:
        raise HTTPException(status_code=500, detail=f"Error processing the image: {e}")

@app.get("/hide_details")
async def anonymize_image(request: Request):
    image_url = request.query_params.get('image_url')
    print(image_url)
    
    try:
        # Fetch the image from the URL
        response = requests.get(image_url)
        response.raise_for_status()
        image = Image.open(BytesIO(response.content))
        
        file_content = response.content
        content_type = response.headers.get('Content-Type')
        
        all_ocr_results = []
        
        if content_type == "application/pdf":
            images = extract_text_from_pdf(file_content)
            for image in images:
                image_np = np.array(image)
                results = reader.readtext(image_np, paragraph=True)
                all_ocr_results.append((results, image))
        elif content_type.startswith("image/"):
            ocr_results, image = extract_text_from_image(file_content)
            all_ocr_results = [(ocr_results, image)]
        else:
            raise HTTPException(status_code=400, detail="Unsupported file type")
        
        all_anonymized_images = []
        for ocr_results, image in all_ocr_results:
            extracted_text = " ".join([result[1] for result in ocr_results])
            
            # Analyze text using Presidio
            analyzer_results = analyzer.analyze(text=extracted_text, language='en')
            
            # Identify sensitive data locations in the image
            boxes_to_blur = []
            for result in analyzer_results:
                detected_text = extracted_text[result.start:result.end]
                for ocr_result in ocr_results:
                    if detected_text in ocr_result[1]:
                        box = ocr_result[0]
                        boxes_to_blur.append(box)
            
            # Blur sensitive data in the image
            anonymized_image = blur_image(image, boxes_to_blur)
            all_anonymized_images.append(anonymized_image)
        
        # Save the anonymized images to a BytesIO object
        output = io.BytesIO()
        if len(all_anonymized_images) == 1:
            all_anonymized_images[0].save(output, format="PNG")
        else:
            all_anonymized_images[0].save(output, format="PDF", save_all=True, append_images=all_anonymized_images[1:])
        output.seek(0)
        
        return StreamingResponse(output, media_type="application/pdf" if len(all_anonymized_images) > 1 else "image/png")

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
# @app.post("/hide_details")
# async def anonymize_image(media_path: str):
#     # media_path = Request.query_params.get('image_url')

#     try:
#         if not os.path.exists(media_path):
#             raise HTTPException(status_code=400, detail="File does not exist")
        
#         if media_path.endswith(".pdf"):
#             # Convert the first page of the PDF to a JPEG image
#             jpeg_path = "temp.jpg"
#             pdf_to_img(media_path, jpeg_path)
            
#             # Read the generated JPEG image
#             with open(jpeg_path, "rb") as img_file:
#                 image_content = img_file.read()
            
#             ocr_results, image = extract_text_from_image(image_content)
#             all_ocr_results = [(ocr_results, image)]
            
#             # Clean up temporary files
#             os.remove(jpeg_path)

#         elif media_path.lower().endswith((".png", ".jpg", ".jpeg", ".bmp", ".gif")):
#             with open(media_path, "rb") as img_file:
#                 image_content = img_file.read()
#             ocr_results, image = extract_text_from_image(image_content)
#             all_ocr_results = [(ocr_results, image)]
#         else:
#             raise HTTPException(status_code=400, detail="Unsupported file type")
        
#         all_anonymized_images = []
#         for ocr_results, image in all_ocr_results:
#             extracted_text = " ".join([result[1] for result in ocr_results])
            
#             # Analyze text using Presidio
#             analyzer_results = analyzer.analyze(text=extracted_text, language='en')
            
#             # Identify sensitive data locations in the image
#             boxes_to_blur = []
#             for result in analyzer_results:
#                 detected_text = extracted_text[result.start:result.end]
#                 for ocr_result in ocr_results:
#                     if detected_text in ocr_result[1]:
#                         box = ocr_result[0]
#                         boxes_to_blur.append(box)
            
#             # Blur sensitive data in the image
#             anonymized_image = blur_image(image, boxes_to_blur)
#             all_anonymized_images.append(anonymized_image)
        
#         # Save the anonymized image to a file
#         output_path = "anonymized_image.png" if len(all_anonymized_images) == 1 else "anonymized_document.pdf"
#         if len(all_anonymized_images) == 1:
#             all_anonymized_images[0].save(output_path, format="PNG")
#         else:
#             all_anonymized_images[0].save(output_path, format="PDF", save_all=True, append_images=all_anonymized_images[1:])
        
#         return JSONResponse(content={"anonymized_image_path": output_path})

#     except Exception as e:
#         raise HTTPException(status_code=500, detail=str(e))

# @app.get("/verify_seal")
# async def verify_seal(request: Request):
#     path = str(request.query_params.get("path"))
#     print(path)
#     try:
#         # Check if the path is a URL
#         if path.startswith("http://") or path.startswith("https://"):
#             try:
#                 # Download the file from URL
#                 response = requests.get(path)
#                 response.raise_for_status()  # Raise error for bad status codes
#                 # Save the file locally
#                 local_file_path = "temp_file"
#                 with open(local_file_path, 'wb') as file:
#                     file.write(response.content)
#                 file_location = local_file_path
#             except requests.exceptions.RequestException as e:
#                 raise HTTPException(status_code=400, detail="Failed to download file from URL")
#         else:
#             # Assume path is a local file path
#             if not os.path.exists(path):
#                 raise HTTPException(status_code=400, detail="File does not exist")
#             file_location = path

#         # Determine the file type and process accordingly
#         if file_location.lower().endswith(".pdf"):
#             # Convert the first page of the PDF to a JPEG image
#             jpeg_path = "temp.jpg"
#             pdf_to_img(file_location, jpeg_path)
#             file_location = jpeg_path
#         elif file_location.lower().endswith((".png", ".jpg", ".jpeg", ".bmp", ".gif")):
#             pass  # No conversion needed for supported image types
#         else:
#             raise HTTPException(status_code=400, detail="Unsupported file type")

#         # Perform seal verification
#         result = seal_verification(file_location)

#         # Clean up temporary files if necessary
#         if os.path.exists(file_location):
#             os.remove(file_location)

#         return JSONResponse(content=result)

#     except Exception as e:
#         return JSONResponse(content={"error": str(e)})
@app.get("/verify_seal")
async def verify_seal(request: Request):
    path = str(request.query_params.get("path"))
    print(path)
    try:
        if path.startswith("http://") or path.startswith("https://"):
            # Handle URL download
            try:
                response = requests.get(path)
                response.raise_for_status()  # Raise error for bad status codes
                file_location = f"temp_file"
                with open(file_location, 'wb') as file:
                    file.write(response.content)
            except requests.exceptions.RequestException as e:
                raise HTTPException(status_code=400, detail="Failed to download file from URL")
        else:
            # Assume path is a local file path
            if not os.path.exists(path):
                raise HTTPException(status_code=400, detail="File does not exist")
            file_location = path

        # Perform seal verification
        result = seal_verification(file_location)

        # Clean up temporary files if necessary
        if os.path.exists(file_location):
            os.remove(file_location)
        print(result)
        return JSONResponse(content=result)

    except Exception as e:
        return JSONResponse(content={"error": str(e)})




@app.get("/process_image")
async def process_image(request: Request):
    try:
        path = str(request.query_params.get('path'))
        full_name = str(request.query_params.get('full_name'))
        name_inti = str(request.query_params.get('name_inti'))
        address = str(request.query_params.get('address'))
        age = str(request.query_params.get('age'))

        if not path:
            raise HTTPException(status_code=400, detail="Path parameter is required")

        # Check if the path is a URL
        if path.startswith("http://") or path.startswith("https://"):
            try:
                # Download the image from URL
                response = requests.get(path)
                response.raise_for_status()  # Raise error for bad status codes
                # Save the image locally
                local_image_path = f"temp_image.jpg"
                with open(local_image_path, 'wb') as file:
                    file.write(response.content)
                image_path = local_image_path
            except requests.exceptions.RequestException as e:
                raise HTTPException(status_code=400, detail="Failed to download image from URL")
        else:
            # Assume path is a local file path
            if not os.path.exists(path):
                raise HTTPException(status_code=400, detail="File does not exist")
            image_path = path

        # Determine the file extension
        file_extension = image_path.split('.')[-1].lower()

        # Process based on file extension
        if file_extension == "pdf":
            # Convert PDF to image
            image_path = f"temp_{os.path.basename(path).split('.')[0]}.jpg"
            pdf_to_img(path, image_path)

        # Perform OCR on the image
        text_easy = easy_ocr(image_path)
        text_keras = keras_ocr(image_path)
        combined_text = f"{text_easy} {text_keras}"

        # Clean up temporary files if necessary
        if file_extension == "pdf":
            os.remove(image_path)

        # Calculate scores using a scoring function
        name_score, address_score, age_score = score_fun(
            full_name,
            name_inti,
            address,
            age,
            combined_text
        )

        # Return scores as JSON response
        return JSONResponse({"name_score": name_score, "address_score": address_score, "age_score": age_score})

    except Exception as e:
        print(f"Error processing image: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")
@app.get('/Password_user_anomaly_detection')
def predict(request: Request):
    print("AAA")
    # password_length = request.args.get('passwordLength', type=int)
    password_length = int(request.query_params.get('passwordLength'))
    avg_typing_time = float(request.query_params.get('avgTypingTime'))
    inter_key_delay = float(request.query_params.get('interKeyTime'))
    total_typing_time = float(request.query_params.get('totalTypingTime'))
    print(password_length)
    print(avg_typing_time)
    print(inter_key_delay)
    print(total_typing_time)
    print("Hiiiiii")
    # Convert the incoming data to a DataFrame
    new_data = pd.DataFrame([{
        'password_length': password_length,
        'avg_typing_time': avg_typing_time,
        'inter_key_delay': inter_key_delay,
        'total_typing_time': total_typing_time
    }])
    
    print("Tata")
    # Standardize the new data
    new_data_scaled = password_scaler.transform(new_data)
    
    # Make prediction using the best model
    prediction = password_user_anomaly_model.predict(new_data_scaled)
    prediction_proba = password_user_anomaly_model.predict_proba(new_data_scaled)
    
    print("Bhai")
    # Return the prediction result
    result = {
        'prediction': 'Bot' if prediction[0] == 1 else 'Human',
        'probability': prediction_proba[0].tolist()  # Convert to list for JSON serialization
    }
    print(result)
    return JSONResponse(result)


@app.get("/user_anomaly_detection")
def user_anomaly_detection(request: Request):
    endpoint_count = int(request.query_params.get('endpoint_count'))
    login_attempts = int(request.query_params.get('login_attempts'))
    session_duration = float(request.query_params.get('session_duration'))
    data_transferred_mb = float(request.query_params.get('data_transferred_mb'))
    
    try:
        processed_data = preprocess_new_data(endpoint_count, login_attempts, session_duration, data_transferred_mb)
        prediction = Password_user_anomaly_detection_model.predict(processed_data)[0]  # Get the first prediction (assuming batch size 1)
        
        if prediction == 0:
            response_data = {"prediction": "Human"}
        elif prediction == 1:
            response_data = {"prediction": "Anomaly"}
        else:
            raise HTTPException(status_code=500, detail="Invalid prediction value")
        
        return JSONResponse(content=response_data)
    
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    

def to_markdown(text):
    text = text.replace("•", "  *")
    return Markdown(textwrap.indent(text, "> ", predicate=lambda _: True))

@app.post("/verify-document/")
async def verify_document(file: UploadFile = File(...)):
    contents = await file.read()
    image = Image.open(io.BytesIO(contents))

    # Assuming 'img' is the image data required by the model
    response = gemini_model.generate_content([
        """
        You are an expert system designed to verify medical documents. 
        Please analyze the image and provide the following information:
        
        The name of the hospital from the document's header.
        The name of the hospital from the seal present in the document.
        Check if the hospital name in the header matches the hospital name in the seal. 
        If they match, return 'Verified'. If they do not match, return 'Not Verified'.
        Note that OUTPUT should be "VERIFIED" or "NOT VERIFIED".
        If the uploaded image is not related to a medical document, please return "INVALID DOCUMENT".
        """, image], stream=True)
    response.resolve()

    markdown_response = to_markdown(response.text)
    return {"result": markdown_response}
    
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
