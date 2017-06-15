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
"""

import time
from urllib import request
from urllib.request import urlopen
import os.path
import tarfile

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.feature_extraction.text import CountVectorizer

import phe as paillier

np.random.seed(42)

# Enron spam dataset
url1 = 'http://www.aueb.gr/users/ion/data/enron-spam/preprocessed/enron1.tar.gz'
url2 = 'http://www.aueb.gr/users/ion/data/enron-spam/preprocessed/enron2.tar.gz'


def download_data():

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

    # Words count
    count_vect = CountVectorizer(decode_error='replace')
    X = count_vect.fit_transform(X)

    # Shuffle
    perm = np.random.permutation(X.shape[0])
    X, y = X[perm, :], y[perm]

    # Split train and test
    X_train, X_test = X[-1000:, :50], X[:-1000, :50]
    y_train, y_test = y[-1000:], y[:-1000]

    return X_train, y_train, X_test, y_test

    # Remove small alphanumerical string
    # pattern = re.compile('[\D_]+')
    # for i in range(len(X_train)):
    #     X_train[i] = [word for word in X_train[i]
    #                   if len(pattern.sub('', word)) >= 3]
    # for i in range(len(X_test)):
    #     X_test[i] = [word for word in X_test[i]
    #                  if len(pattern.sub('', word)) >= 3]


class TimeIt():

    def tick(self):
        self.time0 = time.time()

    def tock(self):
        if not self.time0:
            raise Exception('Need to `tick` first!')

        time1 = time.time() - self.time0
        print('==> elapsed time: %.2f s' % time1)


class PaillierClassifier():

    def __init__(self, pubkey):
        self.pubkey = pubkey

    def set_weights(self, weights, intercept):
        self.weights = np.array(weights)
        self.intercept = intercept

    def encrypted_predict(self, x):

        score = self.intercept
        for idx in np.arange(x.shape[1]):
            if x[0, idx] > 0.0:
                score += float(x[0, idx]) * self.weights[idx]
        return score

    def encrypted_evaluate(self, X):
        return [self.encrypted_predict(X[i, :]) for i in np.arange(X.shape[0])]


# class Alice():
#     """
#     Train a model on clear data.
#     Possess the private key and can encrypt the model for remote usage.
#     """
#
#     def __init__(self):
#         pass
#
#
# class Bob():
#     """
#     Possess the public key and can score data based on encrypted model.
#     """
#
#     def __init__(self):
#         pass


if __name__ == '__main__':

    download_data()
    X, y, X_test, y_test = preprocess_data()

    timer = TimeIt()

    print("Generating paillier keypair")
    pubkey, prikey = paillier.generate_paillier_keypair(n_length=1024)

    print("Learning spam classifier")
    timer.tick()
    model = LogisticRegression()
    model = model.fit(X, y)
    timer.tock()

    print("Classify with model in the clear -- what Alice would get having Bob's data locally")
    timer.tick()
    error = np.mean(model.predict(X_test) != y_test)
    timer.tock()
    print("Error %.4f" % error)

    print("Encrypting classifier")
    timer.tick()
    encrypted_weights = []
    for w in np.nditer(model.coef_):
        encrypted_weights.append(pubkey.encrypt(float(w)))
    encrypted_intercept = pubkey.encrypt(model.intercept_[0])
    timer.tock()

    print("Scoring with encrypted classifier")
    timer.tick()
    cl = PaillierClassifier(pubkey)
    cl.set_weights(encrypted_weights, encrypted_intercept)
    encrypted_scores = cl.encrypted_evaluate(X_test)
    timer.tock()

    print("Decrypt scores and compute error")
    timer.tick()
    scores = [prikey.decrypt(s) for s in encrypted_scores]
    error = np.mean(np.sign(scores) != y_test)
    timer.tock()
    print("Error %.4f" % error)
