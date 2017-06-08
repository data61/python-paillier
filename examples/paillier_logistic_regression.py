"""
Example inspired by @iamtrask blog post:
https://iamtrask.github.io/2017/06/05/homomorphic-surveillance/

In this example we train a spam classifier with logistic regression. The
training data is assumed to be known in the clear. After learning, the model
is encrypted and used for prediction only in this form.
"""

import phe as paillier
import numpy as np
from collections import Counter
from urllib import request
import os.path

np.random.seed(12345)

# TODO: we should rely on data from an open source data repository
data_url = 'https://iamtrask.github.io/data/'
ham_file = 'ham.txt'
spam_file = 'spam.txt'

def get_data():

    # Getting data the remote
    if not os.path.isfile(ham_file):
        print("Downloading", data_url + ham_file)
        with request.urlopen(data_url + ham_file) as hamdata:
            with open(ham_file, 'wb') as hamfile:
                hamfile.write(hamdata.read())
    if not os.path.isfile(spam_file):
        print("Downloading", data_url + spam_file)
        with request.urlopen(data_url + spam_file) as spamdata:
            with open(spam_file, 'wb') as spamfile:
                spamfile.write(spamdata.read())

    # Bring it up from disk
    print("Importing dataset from disk...")
    with open(ham_file, 'rb') as f:
        ham = [row[:-2].split(b" ") for row in f.readlines()]

    with open(spam_file, 'rb') as f:
        spam = [row[:-2].split(b" ") for row in f.readlines()]

    # Prepare for text processing.

    return ham, spam


class LogisticRegression():
    def __init__(self, positives, negatives, iterations=10, alpha=0.1):

        self.encrypted = False
        self.maxweight = 10

        # Create vocabulary (real world use case would add a few million
        # other terms as well from a big internet scrape)
        cnts = Counter()
        for email in (positives + negatives):
            for word in email:
                cnts[word] += 1

        # Convert to lookup table
        vocab = list(cnts.keys())
        self.word2index = {}
        for i, word in enumerate(vocab):
            self.word2index[word] = i

        # Initialize decrypted weights
        self.weights = (np.random.rand(len(vocab)) - 0.5) * 0.1

        # Train model on unencrypted information
        self.train(positives, negatives, iterations=iterations, alpha=alpha)

    def train(self, positives, negatives, iterations=10, alpha=0.1):

        for iter in range(iterations):
            error = 0
            n = 0
            for i in range(max(len(positives), len(negatives))):
                error += np.abs(self.learn(positives[i % len(positives)], 1, alpha))
                error += np.abs(self.learn(negatives[i % len(negatives)], 0, alpha))
                n += 2

            print("Iter:{} Loss: {:.6f}".format(iter, error / float(n)))

    def softmax(self, x):
        # Avoiding overflow trick from
        # http://fa.bianp.net/blog/2013/numerical-optimizers-for-logistic-regression/
        if x > 0:
            return 1 / (1 + np.exp(-x))
        else:
            exp_t = np.exp(x)
            return exp_t / (1. + exp_t)

    # def encrypt(self, pubkey, scaling_factor=1000):
    def encrypt(self, pubkey):
        if (not self.encrypted):
            self.pubkey = pubkey
            # self.scaling_factor = float(scaling_factor)
            self.encrypted_weights = list()

            for weight in self.weights:
                # self.encrypted_weights.append(self.pubkey.encrypt(
                #         int(min(weight, self.maxweight) * self.scaling_factor)))

                self.encrypted_weights.append(self.pubkey.encrypt(weight))

                self.encrypted = True
                self.weights = None

            return self

    def predict(self, email):
        if self.encrypted:
            return self.encrypted_predict(email)
        else:
            return self.unencrypted_predict(email)

    def encrypted_predict(self, email):
        pred = self.pubkey.encrypt(0)
        for word in email:
            pred += self.encrypted_weights[self.word2index[word]]
        return pred

    def unencrypted_predict(self, email):
        pred = 0
        for word in email:
            pred += self.weights[self.word2index[word]]
        pred = self.softmax(pred)
        return pred

    def learn(self, email, target, alpha):
        pred = self.predict(email)
        delta = (pred - target)  # * pred * (1 - pred)
        for word in email:
            self.weights[self.word2index[word]] -= delta * alpha
        return delta

    def evaluate(self):

        # Generate encrypted predictions. Then decrypt them and evaluate.
        fp, tn, tp, fn = .0, .0, .0, .0

        for i, h in enumerate(ham[-1000:]):
            encrypted_pred = encrypted_model.predict(h)
            try:
                # pred = prikey.decrypt(encrypted_pred) / encrypted_model.scaling_factor
                pred = prikey.decrypt(encrypted_pred)
                if pred < 0:
                    tn += 1
                else:
                    fp += 1
            except:
                print("overflow")


        for i, h in enumerate(spam[-1000:]):
            encrypted_pred = encrypted_model.predict(h)
            try:
                pred = prikey.decrypt(encrypted_pred)
                if pred > 0:
                    tp += 1
                else:
                    fn += 1
            except:
                print("overflow")

        print('Evaluated {:3d} ham and spam emails'.format(tn + tp + fn + fp))

        print("Encrypted Accuracy: {:.2f}%".format(100 * (tn + tp) / float(tn + tp + fn + fp)))
        print("False Positives: {:.2f}%     <- privacy violation level".format(100 * fp / float(tp + fp)))
        print("False Negatives: {:.2f}%     <- security risk level".format(100 * fn / float(tn + fn)))


if __name__ == '__main__':

    ham, spam = get_data()

    print("Generating paillier keypair")
    pubkey, prikey = paillier.generate_paillier_keypair(n_length=1024)

    print("Learning spam classifier")
    model = LogisticRegression(spam[0:-1000], ham[0:-1000], iterations=10)

    print("Encrypting classifier")
    encrypted_model = model.encrypt(pubkey)

    print("Evaluating with encrypted model")
