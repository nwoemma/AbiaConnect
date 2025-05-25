import pickle

with open('tokenizer.pkl', 'rb') as f:
    data = pickle.load(f)


print("Vocabulary size:", len(data.word_index))
print("Word index sample:", dict(list(data.word_index.items())[:10]))