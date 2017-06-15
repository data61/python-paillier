"""
In this example Alice train a spam classifier on some email dataset she owns.
She wants to apply it to Bob's personal emails, without

1) asking Bob to send his emails anywhere
1) leaking information about the learned model or the dataset she has used
2) letting Bob know which of his e-mails are spam or not.

Alice trains a spam classifier with logistic regression on some data she
posseses. After learning, generate public and privacy key with a Paillier
schema. The model is encrypted with the private key. The public key is sent to
Bob. Bob applies the encrypted model to his own data, obtaining encrypted
scores for each email. Bob sends them to Alice. Alice decrypts them with the
public key and computes the error.

Example inspired by @iamtrask blog post:
https://iamtrask.github.io/2017/06/05/homomorphic-surveillance/

Dependencies: numpy, sklearn, urllib
"""

import time
import os.path
import tarfile
from urllib.request import urlopen

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.feature_extraction.text import CountVectorizer

import phe as paillier

np.random.seed(42)

# Enron spam dataset
url1 = 'http://www.aueb.gr/users/ion/data/enron-spam/preprocessed/enron1.tar.gz'
url2 = 'http://www.aueb.gr/users/ion/data/enron-spam/preprocessed/enron2.tar.gz'


def download_data():
    """Download two sets of Enron1 spam/ham emails if they are not here"""

    if (not os.path.isdir('examples/enron1') or
        not os.path.isdir('examples/enron2')):

        print("Downloading 1/2:", url1)
        # First folder -> train set
        foldertar = 'examples/emails.tar.gz'

        with urlopen(url1) as remotedata:
            with open(foldertar, 'wb') as tar:
                tar.write(remotedata.read())

        with tarfile.open(foldertar) as tar:
            tar.extractall('examples/')
        os.remove(foldertar)

        # Second folder -> test set
        print("Downloading 2/2:", url2)
        with urlopen(url2) as remotedata:
            with open(foldertar, 'wb') as tar:
                tar.write(remotedata.read())

        with tarfile.open(foldertar) as tar:
            tar.extractall('examples/')
        os.remove(foldertar)


def preprocess_data():
    """
    Get the Enron emails from disk.
    Represent them as bag-of-words.
    Shuffle and split train/test.
    """

    print("Importing dataset from disk...")
    path = 'examples/enron1/ham/'
    ham1 = [open(path + f, 'r', errors='replace').read().strip(r"\n")
            for f in os.listdir(path) if os.path.isfile(path + f)]
    path = 'examples/enron1/spam/'
    spam1 = [open(path + f, 'r', errors='replace').read().strip(r"\n")
             for f in os.listdir(path) if os.path.isfile(path + f)]
    path = 'examples/enron2/ham/'
    ham2 = [open(path + f, 'r', errors='replace').read().strip(r"\n")
            for f in os.listdir(path) if os.path.isfile(path + f)]
    path = 'examples/enron2/spam/'
    spam2 = [open(path + f, 'r', errors='replace').read().strip(r"\n")
             for f in os.listdir(path) if os.path.isfile(path + f)]

    # Merge and create labels
    X = ham1 + spam1 + ham2 + spam2
    y = np.array([-1] * len(ham1) + [1] * len(spam1) +
                 [-1] * len(ham2) + [1] * len(spam2))

    # Words count, keep only fequent words
    count_vect = CountVectorizer(decode_error='replace', stop_words='english',
                                 min_df=0.001)
    X = count_vect.fit_transform(X)

    print('Vocabulary size: %d' % X.shape[1])

    # Shuffle
    perm = np.random.permutation(X.shape[0])
    X, y = X[perm, :], y[perm]

    # Split train and test
    split = 500
    X_train, X_test = X[-split:,], X[:-split,]
    y_train, y_test = y[-split:], y[:-split]

    print("Labels in trainset are %.2f spam / %.2f ham"
           % (np.mean(y_train == 1), np.mean(y_train == -1)))

    return X_train, y_train, X_test, y_test


class TimeIt():
    """Helper for measuring runtime"""

    def tick(self):
        self.time0 = time.time()

    def tock(self):
        if not self.time0:
            raise Exception('Need to `tick` first!')

        time1 = time.time() - self.time0
        print('[elapsed time: %.2f s]' % time1)


class PaillierClassifier():
    """Scorer of emails with an encrypted models"""

    def __init__(self, pubkey):
        self.pubkey = pubkey

    def set_weights(self, weights, intercept):
        self.weights = np.array(weights)
        self.intercept = intercept

    def encrypted_predict(self, x):

        score = self.intercept
        _, idx = x.nonzero()
        for i in idx:
            score += float(x[0, i]) * self.weights[i]
        return score

    def encrypted_evaluate(self, X):
        return [self.encrypted_predict(X[i, :]) for i in np.arange(X.shape[0])]


class Alice():
    """
    Train a model on clear data.
    Possess the private key and can encrypt the model for remote usage.
    """

    def __init__(self):
        self.model = LogisticRegression()

    def generate_paillier_keypair(self, n_length):
        self.pubkey, self.privkey = \
            paillier.generate_paillier_keypair(n_length=n_length)

    def get_pubkey(self):
        return self.pubkey

    def fit(self, X, y):
        self.model = self.model.fit(X, y)

    def predict(self, X):
        return self.model.predict(X)

    def encrypt_weights(self):
        encrypted_weights = []
        for w in np.nditer(self.model.coef_):
            encrypted_weights.append(self.pubkey.encrypt(float(w)))
        encrypted_intercept = self.pubkey.encrypt(self.model.intercept_[0])
        return encrypted_weights, encrypted_intercept

    def decrypt_scores(self, encrypted_scores):
        return [self.privkey.decrypt(s) for s in encrypted_scores]


class Bob():
    """
    Possess the public key and can score data based on encrypted model.
    """

    def __init__(self, pubkey):
        self.classifier = PaillierClassifier(pubkey)

    def set_weights(self, weights, intercept):
        self.classifier.set_weights(weights, intercept)

    def encrypted_predict(self, x):
        return self.classifier(x)

    def encrypted_evaluate(self, X):
        return self.classifier.encrypted_evaluate(X)


if __name__ == '__main__':

    timer = TimeIt()

    download_data()
    X, y, X_test, y_test = preprocess_data()

    print("Generating paillier keypair")
    alice = Alice()
    # NOTE: using smaller keys sizes wouldn't be criptographically safe
    alice.generate_paillier_keypair(n_length=1024)

    print("\nLearning spam classifier")
    timer.tick()
    alice.fit(X, y)
    timer.tock()

    print("Classify with model in the clear -- what Alice would get having Bob's data locally")
    timer.tick()
    error = np.mean(alice.predict(X_test) != y_test)
    timer.tock()
    print("Error %.3f" % error)

    print("Encrypting classifier")
    timer.tick()
    encrypted_weights, encrypted_intercept = alice.encrypt_weights()
    timer.tock()

    print("Scoring with encrypted classifier")
    bob = Bob(alice.get_pubkey())
    bob.set_weights(encrypted_weights, encrypted_intercept)
    timer.tick()
    encrypted_scores = bob.encrypted_evaluate(X_test)
    timer.tock()

    print("Decrypt scores and compute error")
    timer.tick()
    scores = alice.decrypt_scores(encrypted_scores)
    error = np.mean(np.sign(scores) != y_test)
    timer.tock()
    print("Error %.3f" % error)