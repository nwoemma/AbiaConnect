import os
from transformers import pipeline
from chats.models import Category

# Transformer-based classification pipeline
MODEL_NAME = os.getenv('CLASSIFIER_MODEL', 'distilbert-base-uncased-finetuned-sst-2-english')
classifier = pipeline('text-classification', model=MODEL_NAME)

def categorize_message(text: str) -> str:
    """
    Uses a transformer model to classify the text into one of our predefined categories.
    Returns the Category code.
    """
    result = classifier(text, truncation=True)[0]
    label = result['label'].upper()
    # Map model labels to our Category codes
    if 'EMERGENCY' in label or 'URGENT' in label:
        return Category.EMERGENCY
    if 'SUGGESTION' in label:
        return Category.SUGGESTION
    if 'PROJECT' in label:
        return Category.PROJECT_FEEDBACK
    return Category.HUMAN_DEVELOPMENT

