import re
import unicodedata
from difflib import SequenceMatcher

from django.db.models import Q
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np

from .models import MessageKnowledgeBase, URLKnowledgeBase

def normalize_text(text):
    if not text:
        return ""
    text = unicodedata.normalize('NFKD', text)
    text = text.lower()
    text = re.sub(r'[^\w\s]', '', text)
    return re.sub(r'\s+', ' ', text).strip()

def extract_urls(text):
    if not text:
        return []
    url_pattern = r'https?://[^\s<>\"]+|www\.[^\s<>\"]+'
    return re.findall(url_pattern, text, re.IGNORECASE)

def calculate_risk_score(text, urls):
    score = 0
    matched_fraud = []
    matched_legit = []
    matched_urls_phishing = []
    matched_urls_legit = []
    explanations = []

    normalized_text = normalize_text(text)
    
    # 1. Fetch active Knowledge Base
    fraud_records = MessageKnowledgeBase.objects.filter(classification='fraudulent', is_active=True)
    legit_records = MessageKnowledgeBase.objects.filter(classification='legitimate', is_active=True)
    phishing_urls = URLKnowledgeBase.objects.filter(classification='phishing', is_active=True)
    legit_urls = URLKnowledgeBase.objects.filter(classification='legitimate', is_active=True)

    # 2. Exact and Fuzzy Matching (Text)
    for record in fraud_records:
        norm_record = normalize_text(record.content)
        ratio = SequenceMatcher(None, normalized_text, norm_record).ratio()
        if ratio > 0.70: # High similarity
            score += 50
            matched_fraud.append(record.content[:50])
            explanations.append(f"High similarity to known fraud: '{record.content[:30]}...'")
            break # Cap exact match bonus

    for record in legit_records:
        norm_record = normalize_text(record.content)
        ratio = SequenceMatcher(None, normalized_text, norm_record).ratio()
        if ratio > 0.90: # Strict match for legit to prevent false positives
            score -= 40
            matched_legit.append(record.content[:50])
            explanations.append(f"Matches legitimate template: '{record.content[:30]}...'")

    # 3. TF-IDF Cosine Similarity (Semantic)
    all_kb_texts = list(fraud_records.values_list('content', flat=True)) + list(legit_records.values_list('content', flat=True))
    if all_kb_texts and normalized_text:
        try:
            vectorizer = TfidfVectorizer(stop_words='english')
            tfidf_matrix = vectorizer.fit_transform(all_kb_texts + [normalized_text])
            input_vec = tfidf_matrix[-1]
            kb_vecs = tfidf_matrix[:-1]
            
            similarities = cosine_similarity(input_vec, kb_vecs)[0]
            
            # Check fraud similarities
            fraud_count = fraud_records.count()
            if fraud_count > 0:
                max_fraud_sim = np.max(similarities[:fraud_count])
                if max_fraud_sim > 0.25:
                    score += 30
                    explanations.append(f"Semantic similarity to fraud patterns ({max_fraud_sim:.2f}).")
            
            # Check legit similarities
            if fraud_count < len(similarities):
                max_legit_sim = np.max(similarities[fraud_count:])
                if max_legit_sim > 0.75:
                    score -= 20
                    explanations.append(f"Semantic similarity to legitimate patterns ({max_legit_sim:.2f}).")
        except Exception:
            pass # Ignore TF-IDF errors on empty or weird data

    # 4. Urgency & Threat Keyword Detection (High Priority)
    urgency_keywords = ["urgent", "immediately", "within 24 hours", "delete", "suspended", "locked", "threat", "unusual login", "new device", "secure your account", "delivery fee", "bvn", "fraudulent activities", "regularize your account", "won a free", "pay a small", "claim your prize", "send your bvn"]
    for kw in urgency_keywords:
        if kw in normalized_text:
            score += 30
            if kw not in explanations:
                explanations.append(f"Urgency/threat keyword detected: '{kw}'")
    
    # 4b. Standard Keyword Matching
    high_risk_keywords = []
    for record in fraud_records:
        if record.keywords:
            high_risk_keywords.extend([k.strip().lower() for k in record.keywords.split(',') if k.strip()])
    
    keyword_hits = 0
    for kw in set(high_risk_keywords):
        if kw in normalized_text:
            keyword_hits += 1
            if keyword_hits <= 3: # Cap at 3 keywords
                score += 10
    
    if keyword_hits > 0:
        explanations.append(f"Detected {keyword_hits} high-risk keyword(s).")

    # 5. URL Matching
    for url in urls:
        from urllib.parse import urlparse
        url_domain = urlparse(url).netloc.replace('www.', '').lower()
        
        for p_url in phishing_urls:
            if p_url.domain.lower() in url_domain or url_domain in p_url.domain.lower():
                score += 40
                matched_urls_phishing.append(url)
                explanations.append(f"Known phishing URL detected: {url}")
                break
        
        for l_url in legit_urls:
            if l_url.domain.lower() in url_domain or url_domain in l_url.domain.lower():
                score -= 20
                matched_urls_legit.append(url)
                explanations.append(f"Known legitimate URL detected: {url}")
                break

    # Clamp score
    score = max(0, min(100, score))
    return score, explanations, matched_fraud, matched_legit, matched_urls_phishing, matched_urls_legit

def classify_score(score):
    if score >= 75:
        return "Fraudulent", "critical", 0.95
    elif score >= 50:
        return "Suspicious", "high", 0.80
    elif score >= 25:
        return "Likely Legitimate", "low", 0.60
    else:
        return "Inconclusive", "low", 0.40

def analyze_message(text):
    if not text or not text.strip():
        return {
            "label": "Inconclusive",
            "severity": "low",
            "confidence": 0.0,
            "explanation": "Empty or invalid message submitted.",
            "recommendation": "Please submit a valid message for analysis.",
            "feature_summary": {"error": "empty_input"}
        }

    urls = extract_urls(text)
    score, explanations, matched_fraud, matched_legit, matched_urls_phishing, matched_urls_legit = calculate_risk_score(text, urls)
    label, severity, confidence = classify_score(score)

    if label in ["Fraudulent", "Suspicious"]:
        recommendation = "Do not click any links. Report this message to your bank or relevant authorities immediately."
    else:
        recommendation = "This message appears safe, but always verify sender details independently."

    return {
        "label": label,
        "severity": severity,
        "confidence": confidence,
        "explanation": " | ".join(explanations) if explanations else "No specific indicators matched the knowledge base.",
        "recommendation": recommendation,
        "feature_summary": {
            "risk_score": score,
            "urls_found": urls,
            "matched_fraud_snippets": matched_fraud,
            "matched_legit_snippets": matched_legit,
            "phishing_urls": matched_urls_phishing,
            "legitimate_urls": matched_urls_legit
        }
    }
