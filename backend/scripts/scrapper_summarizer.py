from bs4 import BeautifulSoup
import requests
from transformers import pipeline
from transformers import PegasusForConditionalGeneration, PegasusTokenizer


def scrape_website(url):
    response = requests.get(url)
    if response.status_code == 200:
        soup = BeautifulSoup(response.content, 'html.parser')
        paragraphs = soup.find_all('p')
        text = ' '.join([p.get_text() for p in paragraphs])
        return text
    else:
        raise Exception(f"Failed to fetch URL: {url}, Status Code: {response.status_code}")


def summarize_with_pegasus(url, max_chunk_size=512):
    text=scrape_website(url)
    summarizer = pipeline("summarization", model="google/pegasus-xsum")
    chunks = [text[i:i+max_chunk_size] for i in range(0, len(text), max_chunk_size)]
    summaries = []
    for chunk in chunks:
        summary = summarizer(chunk, max_length=60, min_length=20, do_sample=False)
        summaries.append(summary[0]['summary_text'])
    
    return " ".join(summaries)



def extract_title(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.content, 'html.parser')
    title = soup.title.string
    return title



