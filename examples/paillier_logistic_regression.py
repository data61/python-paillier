"""
Example inspired by @iamtrask blog post:
https://iamtrask.github.io/2017/06/05/homomorphic-surveillance/

In this example we train a spam classifier with logistic regression. The
training data is assumed to be known in the clear. After learning, the model
is encrypted and used for prediction only in this form.

Dependencies: scikit-learn
"""

import phe as paillier
import numpy as np
from urllib.request import urlopen
import os.path
import time
import tarfile
import re

seed = 42
np.random.seed(seed)

# Enron spam dataset #1 urllib
url1 = 'http://www.aueb.gr/users/ion/data/enron-spam/preprocessed/enron1.tar.gz'
url2 = 'http://www.aueb.gr/users/ion/data/enron-spam/preprocessed/enron2.tar.gz'


class Timeit():

    def tick(self):
        self.time0 = time.time()

    def tock(self):
        if not self.time0:
            raise Exception('Need to `tick` first!')

        time1 = time.time() - self.time0
        print('--> elapsed time: %.2f s' % time1)


def download_data(cats):

    if (not os.path.isdir('enron1') or not os.path.isdir('enron2')):

        print("Downloading data")
        # First folder -> train set
        foldertar = 'emails.tar.gz'

        with urlopen(url1) as remotedata:
            with open(foldertar, 'wb') as tar:
                tar.write(remotedata.read())

        with tarfile.open(foldertar) as tar:
            tar.extractall()
        os.remove(foldertar)

        # Second folder -> test set
        with urlopen(url2) as remotedata:
            with open(foldertar, 'wb') as tar:
                tar.write(remotedata.read())

        with tarfile.open(foldertar) as tar:
            tar.extractall()
        os.remove(foldertar)


def preprocess_data():

    print("Importing dataset from disk...")
    path = 'enron1/ham/'
    ham1 = [open(path + f, 'r', errors='replace').read().strip(r"\n").split(" ")
            for f in os.listdir(path) if os.path.isfile(path + f)]
    path = 'enron1/spam/'
    spam1 = [open(path + f, 'r', errors='replace').read().strip(r"\n").split(" ")
             for f in os.listdir(path) if os.path.isfile(path + f)]
    path = 'enron2/ham/'
    ham2 = [open(path + f, 'r', errors='replace').read().strip(r"\n").split(" ")
            for f in os.listdir(path) if os.path.isfile(path + f)]
    path = 'enron2/spam/'
    spam2 = [open(path + f, 'r', errors='replace').read().strip(r"\n").split(" ")
             for f in os.listdir(path) if os.path.isfile(path + f)]

    # Build training and test sets
    X_train = ham1 + spam1
    y_train = np.array([-1] * len(ham1) + [1] * len(spam1))
    X_test = ham2 + spam2
    y_test = np.array([-1] * len(ham2) + [1] * len(spam2))

    # Remove small alphanumerical string
    pattern = re.compile('[\D_]+')
    for i in range(len(X_train)):
        X_train[i] = [word for word in X_train[i]
                      if len(pattern.sub('', word)) >= 3]
    for i in range(len(X_test)):
        X_test[i] = [word for word in X_test[i]
                     if len(pattern.sub('', word)) >= 3]

    for w in X_train[:5]:
        print(w)
    exit(0)

    # Create vocabulary
    word2index = {}
    i = 0
    for doc in X_train + X_test:
        for word in doc:
            if word not in word2index:
                word2index[word] = i
                i += 1

    return X_train, y_train, X_test, y_test, word2index


class LogisticRegression():

    def __init__(self, pubkey, privkey, word2index, learn_rate=0.01,
                 verbose=True):

        self.pubkey = pubkey
        self.pivkey = privkey
        self.word2index = word2index
        self.learn_rate = learn_rate
        self.verbose = verbose

        self.weights = np.zeros(len(word2index))
        # Flag indicating whether the internal model is encrypted
        self.encrypted = False

    def _softmax(self, x):
        # Avoiding overflow trick from
        # http://fa.bianp.net/blog/2013/numerical-optimizers-for-logistic-regression/
        if x > 0:
            return 1 / (1 + np.exp(-x))
        else:
            exp_t = np.exp(x)
            return exp_t / (1. + exp_t)

    def _score(self, x):

        score = 0.0
        for word in x:
            score += self.weights[self.word2index[word]]
            # We should also multiply by the current word-feature, but
            # that can only be 1 or 0, and we skip 0s
        return score

    def _encrypted_score(self, x):

        score = 0
        for word in x:
            score += self.encrypted_weights[self.word2index[word]]
            # We should also multiply by the current word-feature, but
            # that can only be 1 or 0, and we skip 0s
        return score

    def fit(self, X, y, iters=10):

        for i in range(iters):
            # Scan data at random
            idx = np.random.permutation(len(X))
            for j in idx:

                grad = (self._softmax(-self._score(X[j])) - (y[j] + 1)/2)

                for word in X[j]:
                    self.weights[self.word2index[word]] -= self.learn_rate * grad
                    # We should also multiply by the current word-feature, but
                    # that can only be 1 or 0, and we skip 0s

            if self.verbose:
                print("Iter: %d" % i)
                self.evaluate(X, y)

        return self

    def encrypt(self):

        if not self.encrypted:
            self.encrypted = True
            self.encrypted_weights = np.empty_like(self.weights)

            for i, weight in enumerate(self.weights):
                self.encrypted_weights[i] = self.pubkey.encrypt(weight)

        return self

    def predict(self, X):

        out = np.zeros(len(X))

        for i, doc in enumerate(X):
            if self.encrypted:
                out[i] = np.sign(self._encrypted_score(doc).decrypt(out[i]))
            else:
                out[i] = np.sign(self._score(doc))

        return out

    def evaluate(self, X, y):

        error = np.mean(self.predict(X) != y)

        if self.verbose:
            print("Error: %.6f" % error)

        return error


if __name__ == '__main__':

    print("Generating paillier keypair")
    # NOTE: using much smaller key sizes wouldn't be safe criptographically
    pubkey, prikey = paillier.generate_paillier_keypair(n_length=1024)

    # Timer util
    timeit = Timeit()

    print("Getting the data ready")
    # Only load categories atheism against space
    cats = ['talk.politics.guns', 'sci.space']
    download_data(cats)
    X_train, y_train, X_test, y_test, word2index = preprocess_data()

    print("The trainset is composed of %d documents made of %d different words"
          % (len(X_train), len(word2index)))
    print("Labels in the trainset are %.2f / %.2f"
          % (np.mean(y_train == 1), np.mean(y_train == -1)))

    print("Learning spam classifier")
    model = LogisticRegression(pubkey, prikey, word2index)
    timeit.tick()
    model = model.fit(X_train, y_train)
    timeit.tock()

    # print("Evaluating with NON-encrypted model")
    # timeit.tick()
    # model.evaluate(encrypted=False)
    # timeit.tock()
    #
    # print("Encrypting classifier")
    # timeit.tick()
    # model = model.encrypt()
    # timeit.tock()
    #
    # print("Evaluating with encrypted model")
    # timeit.tick()
    # model.evaluate(encrypted=True)
    # timeit.tock()
