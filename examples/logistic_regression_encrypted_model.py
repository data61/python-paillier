"""
In this example Alice trains a spam classifier on some e-mails dataset she
owns. She wants to apply it to Bob's personal e-mails, without

1) asking Bob to send his e-mails anywhere
2) leaking information about the learned model or the dataset she has learned
from
3) letting Bob know which of his e-mails are spam or not.

Alice trains a spam classifier with logistic regression on some data she
possesses. After learning, she generates public/private key pair with a
Paillier schema. The model is encrypted with the public key. The public key and
the encrypted model are sent to Bob. Bob applies the encrypted model to his own
data, obtaining encrypted scores for each e-mail. Bob sends them to Alice.
Alice decrypts them with the private key to obtain the predictions spam vs. not
spam.

Example inspired by @iamtrask blog post:
https://iamtrask.github.io/2017/06/05/homomorphic-surveillance/

Dependencies: numpy, sklearn
"""

import time
import os.path
from zipfile import ZipFile
from urllib.request import urlopen
from contextlib import contextmanager

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.feature_extraction.text import CountVectorizer

import phe as paillier

np.random.seed(42)

# Enron spam dataset hosted by https://cloudstor.aarnet.edu.au
url = [
    'https://cloudstor.aarnet.edu.au/plus/index.php/s/RpHZ57z2E3BTiSQ/download',
    'https://cloudstor.aarnet.edu.au/plus/index.php/s/QVD4Xk5Cz3UVYLp/download'
]


def download_data():
    """Download two sets of Enron1 spam/ham e-mails if they are not here
    We will use the first as trainset and the second as testset.
    Return the path prefix to us to load the data from disk."""

    n_datasets = 2
    for d in range(1, n_datasets + 1):
        if not os.path.isdir('enron%d' % d):

            URL = url[d-1]
            print("Downloading %d/%d: %s" % (d, n_datasets, URL))
            folderzip = 'enron%d.zip' % d

            with urlopen(URL) as remotedata:
                with open(folderzip, 'wb') as z:
                    z.write(remotedata.read())

            with ZipFile(folderzip) as z:
                z.extractall()
            os.remove(folderzip)


def preprocess_data():
    """
    Get the Enron e-mails from disk.
    Represent them as bag-of-words.
    Shuffle and split train/test.
    """

    print("Importing dataset from disk...")
    path = 'enron1/ham/'
    ham1 = [open(path + f, 'r', errors='replace').read().strip(r"\n")
            for f in os.listdir(path) if os.path.isfile(path + f)]
    path = 'enron1/spam/'
    spam1 = [open(path + f, 'r', errors='replace').read().strip(r"\n")
             for f in os.listdir(path) if os.path.isfile(path + f)]
    path = 'enron2/ham/'
    ham2 = [open(path + f, 'r', errors='replace').read().strip(r"\n")
            for f in os.listdir(path) if os.path.isfile(path + f)]
    path = 'enron2/spam/'
    spam2 = [open(path + f, 'r', errors='replace').read().strip(r"\n")
             for f in os.listdir(path) if os.path.isfile(path + f)]

    # Merge and create labels
    emails = ham1 + spam1 + ham2 + spam2
    y = np.array([-1] * len(ham1) + [1] * len(spam1) +
                 [-1] * len(ham2) + [1] * len(spam2))

    # Words count, keep only frequent words
    count_vect = CountVectorizer(decode_error='replace', stop_words='english',
                                 min_df=0.001)
    X = count_vect.fit_transform(emails)

    print('Vocabulary size: %d' % X.shape[1])

    # Shuffle
    perm = np.random.permutation(X.shape[0])
    X, y = X[perm, :], y[perm]

    # Split train and test
    split = 500
    X_train, X_test = X[-split:, :], X[:-split, :]
    y_train, y_test = y[-split:], y[:-split]

    print("Labels in trainset are {:.2f} spam : {:.2f} ham".format(
        np.mean(y_train == 1), np.mean(y_train == -1)))

    return X_train, y_train, X_test, y_test


@contextmanager
def timer():
    """Helper for measuring runtime"""

    time0 = time.perf_counter()
    yield
    print('[elapsed time: %.2f s]' % (time.perf_counter() - time0))


class Alice:
    """
    Trains a Logistic Regression model on plaintext data,
    encrypts the model for remote use,
    decrypts encrypted scores using the paillier private key.
    """

    def __init__(self):
        self.model = LogisticRegression()

    def generate_paillier_keypair(self, n_length):
        self.pubkey, self.privkey = \
            paillier.generate_paillier_keypair(n_length=n_length)

    def fit(self, X, y):
        self.model = self.model.fit(X, y)

    def predict(self, X):
        return self.model.predict(X)

    def encrypt_weights(self):
        coef = self.model.coef_[0, :]
        encrypted_weights = [self.pubkey.encrypt(coef[i])
                             for i in range(coef.shape[0])]
        encrypted_intercept = self.pubkey.encrypt(self.model.intercept_[0])
        return encrypted_weights, encrypted_intercept

    def decrypt_scores(self, encrypted_scores):
        return [self.privkey.decrypt(s) for s in encrypted_scores]


class Bob:
    """
    Is given the encrypted model and the public key.

    Scores local plaintext data with the encrypted model, but cannot decrypt
    the scores without the private key held by Alice.
    """

    def __init__(self, pubkey):
        self.pubkey = pubkey

    def set_weights(self, weights, intercept):
        self.weights = weights
        self.intercept = intercept

    def encrypted_score(self, x):
        """Compute the score of `x` by multiplying with the encrypted model,
        which is a vector of `paillier.EncryptedNumber`"""
        score = self.intercept
        _, idx = x.nonzero()
        for i in idx:
            score += x[0, i] * self.weights[i]
        return score

    def encrypted_evaluate(self, X):
        return [self.encrypted_score(X[i, :]) for i in range(X.shape[0])]


if __name__ == '__main__':

    download_data()
    X, y, X_test, y_test = preprocess_data()

    print("Alice: Generating paillier keypair")
    alice = Alice()
    # NOTE: using smaller keys sizes wouldn't be cryptographically safe
    alice.generate_paillier_keypair(n_length=1024)

    print("Alice: Learning spam classifier")
    with timer() as t:
        alice.fit(X, y)

    print("Classify with model in the clear -- "
          "what Alice would get having Bob's data locally")
    with timer() as t:
        error = np.mean(alice.predict(X_test) != y_test)
    print("Error {:.3f}".format(error))

    print("Alice: Encrypting classifier")
    with timer() as t:
        encrypted_weights, encrypted_intercept = alice.encrypt_weights()

    print("Bob: Scoring with encrypted classifier")
    bob = Bob(alice.pubkey)
    bob.set_weights(encrypted_weights, encrypted_intercept)
    with timer() as t:
        encrypted_scores = bob.encrypted_evaluate(X_test)

    print("Alice: Decrypting Bob's scores")
    with timer() as t:
        scores = alice.decrypt_scores(encrypted_scores)
    error = np.mean(np.sign(scores) != y_test)
    print("Error {:.3f} -- this is not known to Alice, who does not possess "
          "the ground truth labels".format(error))
