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
from collections import Counter
from urllib import request
import os.path
import time
from sklearn.datasets import fetch_20newsgroups
from sklearn.feature_extraction.text import TfidfVectorizer

seed = 42
np.random.seed(seed)


class Timeit():

    def tick(self):
        self.time0 = time.time()

    def tock(self):
        if not self.time0:
            raise Exception('Need to `tick` first!')

        time1 = time.time() - self.time0
        print('--> elapsed time: %.2f s' % time1)


def get_data(cats):

    # Getting data the remote
    # trainset = fetch_20newsgroups(subset='train', categories=cats, shuffle=True,
    #                               random_state=seed,
    #                               remove=('headers', 'footers', 'quotes'))
    # testset = fetch_20newsgroups(subset='test', categories=cats, shuffle=True,
    #                              random_state=seed,
    #                              remove=('headers', 'footers', 'quotes'))
    #
    # # Explode sentences
    # X_train = [doc.strip('\n').split(" ") for doc in trainset.data]
    # X_test = [doc.strip('\n').split(" ") for doc in testset.data]

    if not os.path.isfile("ham.txt") or not os.path.isfile('spam.txt'):
        print("Downloading data")
        with request.urlopen("https://iamtrask.github.io/data/ham.txt") as hamdata:
            with open("ham.txt", 'wb') as hamfile:
                hamfile.write(hamdata.read())

        with request.urlopen("https://iamtrask.github.io/data/spam.txt") as spamdata:
            with open("spam.txt", 'wb') as spamfile:
                spamfile.write(spamdata.read())

    print("Generating paillier keypair")
    pubkey, prikey = paillier.generate_paillier_keypair(n_length=1024)

    print("Importing dataset from disk...")
    with open('spam.txt', 'rb') as f:
        spam = [row[:-2].split(b" ") for row in f.readlines()]

    with open('ham.txt', 'rb') as f:
    ham = [row[:-2].split(b" ") for row in f.readlines()]

    # Change label encoding 0,1 -> -1,1
    y_train, y_test = trainset.target, testset.target
    y_train[y_train == 0], y_test[y_test == 0] = -1, -1

    # Create vocabulary (real world use case would add a few million
    # other terms as well from a big internet scrape)
    word2index = {}
    i = 0
    for doc in X_train + X_test:
        for word in doc:
            if word not in word2index:
                word2index[word] = i
                i += 1
    # for doc in X_test:
    #     for word in doc:
    #         if word not in word2index:
    #             word2index[word] = i
    #             i += 1

    return X_train, y_train, X_test, y_test, word2index


class LogisticRegression():

    def __init__(self, pubkey, privkey, word2index, learn_rate=0.001,
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
            for (xi, yi) in zip(X, y):

                grad = self.learn_rate * (self._softmax(-self._score(xi)) - 1.0) * yi
                for word in xi:
                    self.weights[self.word2index[word]] -= grad
                    # We should also multiply by the current word-feature, but
                    # that can only be 1 or 0, and we skip 0s

            if self.verbose:
                print("Iter: %d" % i)
                self.evaluate(X_train, y_train)

        return self

    def encrypt(self):

        if not self.encrypted:
            self.encrypted = True
            self.encrypted_weights = np.empty_like(self.weights)

            for i, weight in enumerate(self.weights):
                encrypted_weights[i] = self.pubkey.encrypt(weight)

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
    X_train, y_train, X_test, y_test, word2index = get_data(cats)

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
