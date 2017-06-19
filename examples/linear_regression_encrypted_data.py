"""
In this example Alice owns sensitive data of 442 hospital patients with a
diabetes condition. Recorded variables are age, sex, body mass index,
average blood pressure, and six blood serum measurements. A last variable
describes a quantitative measure of the disease progression.

Bob is an external consultant hired with the objecting of turning this data
into an actionable model for predicting the disease progression. Due to
the hospital privacy policy:

1) Bob is not allowed to see ANY sensitive variables describing the patients.
2) Moreover, Alice's data cannot leave the hospital premises, not even in
encrypted form.

Bob will perform linear regression. Since no data can be given to Bob, we
implement a protocol from which Bob can requires gradient of the means square
error


Alice trains a spam classifier with logistic regression on some data she
posseses. After learning, generate public and privacy key with a Paillier
schema. The model is encrypted with the private key. The public key is sent to
Bob. Bob applies the encrypted model to his own data, obtaining encrypted
scores for each email. Bob sends them to Alice. Alice decrypts them with the
public key and computes the error.

Dependencies: numpy, sklearn
"""

import time
from contextlib import contextmanager

import numpy as np
from sklearn.datasets import load_diabetes

import phe as paillier

np.random.seed(42)


def get_data():
    """
    Download the diabetes dataset, if it is not here.
    Get the Enron emails from disk.
    Represent them as bag-of-words.
    Shuffle and split train/test.
    """

    print("Download data")
    diabetes = load_diabetes()
    y = diabetes.target
    X = diabetes.data

    # Add constant to emulate intercept
    X = np.c_[X, np.ones(X.shape[0])]

    # The data is already preprocessed
    # Shuffle
    perm = np.random.permutation(X.shape[0])
    X, y = X[perm, :], y[perm]

    # Split train and test
    split = 100
    X_train, X_test = X[-split:, :], X[:-split, :]
    y_train, y_test = y[-split:], y[:-split]

    return X_train, y_train, X_test, y_test


@contextmanager
def timer():
    """Helper for measuring runtime"""

    time0 = time.perf_counter()
    yield
    print('[elapsed time: %.2f s]' % (time.perf_counter() - time0))


def mean_square_error(y_pred, y):
    """
    1/2 * 1/m * \sum_{i=1..m} (y_pred_i - y_i)^2
    """
    return 0.5 * np.mean((y - y_pred) ** 2)

# class PaillierClassifier():
#     """Scorer of emails with an encrypted models"""
#
#     def __init__(self, pubkey):
#         self.pubkey = pubkey
#
#     def set_weights(self, weights, intercept):
#         self.weights = np.array(weights)
#         self.intercept = intercept
#
#     def encrypted_predict(self, x):
#
#         score = self.intercept
#         _, idx = x.nonzero()
#         for i in idx:
#             score += x[0, i] * self.weights[i]
#         return score
#
#     def encrypted_evaluate(self, X):
#         return [self.encrypted_predict(X[i, :]) for i in np.arange(X.shape[0])]
#
#
# class Alice():
#     """
#     Train a model on clear data.
#     Possess the private key and can encrypt the model for remote usage.
#     """
#
#     def __init__(self):
#         self.model = LogisticRegression()
#
#     def generate_paillier_keypair(self, n_length):
#         self.pubkey, self.privkey = \
#             paillier.generate_paillier_keypair(n_length=n_length)
#
#     def get_pubkey(self):
#         return self.pubkey
#
#     def fit(self, X, y):
#         self.model = self.model.fit(X, y)
#
#     def predict(self, X):
#         return self.model.predict(X)
#
#     def encrypt_weights(self):
#         encrypted_weights = []
#         for w in np.nditer(self.model.coef_):
#             encrypted_weights.append(self.pubkey.encrypt(float(w)))
#         encrypted_intercept = self.pubkey.encrypt(self.model.intercept_[0])
#         return encrypted_weights, encrypted_intercept
#
#     def decrypt_scores(self, encrypted_scores):
#         return [self.privkey.decrypt(s) for s in encrypted_scores]
#
#
# class Bob():
#     """
#     Possess the public key and can score data based on encrypted model.
#     """
#
#     def __init__(self, pubkey):
#         self.classifier = PaillierClassifier(pubkey)
#
#     def set_weights(self, weights, intercept):
#         self.classifier.set_weights(weights, intercept)
#
#     def encrypted_predict(self, x):
#         return self.classifier(x)
#
#     def encrypted_evaluate(self, X):
#         return self.classifier.encrypted_evaluate(X)


def encrypt_vector(pubkey, x):
    return [pubkey.encrypt(x[i]) for i in range(x.shape[0])]


def encrypt_matrix(pubkey, X):
    return [encrypt_vector(pubkey, X[i, :]) for i in range(X.shape[0])]


class PaillierLinearRegression():

    def __init__(self, n_iter=60, eta=0.1):
        self.n_iter = n_iter
        self.eta = eta

    def fit(self, X, y):
        length, dim = X.shape
        weights = np.zeros(dim)

        for _ in range(self.n_iter):
            for i in range(length):
                err = weights.dot(X[i, :]) - y[i]
                for j in range(dim):
                    weights[j] -= self.eta * err * X[i, j]

            self.weights = weights
            print('Error %.4f' % mean_square_error(self.predict(X), y))

        # self.weights = np.linalg.inv(X.T.dot(X)).dot(X.T).dot(y)
        # print(self.weights)

        return self

    def fit_encrypted_data(self, X, y):
        length, dim = len(X), len(X[0])
        weights = np.zeros(dim)

        for _ in range(self.n_iter):
            for i in range(length):
                err = weights.dot(X[i, :]) - y[i]
                for j in range(dim):
                    weights[j] -= self.eta * err * X[i, j]

            self.weights = weights
            print('Error %.4f' % mean_square_error(self.predict(X), y))

        # self.weights = np.linalg.inv(X.T.dot(X)).dot(X.T).dot(y)
        # print(self.weights)

        return self

    def predict(self, X):
        return X.dot(self.weights)


if __name__ == '__main__':

    X, y, X_test, y_test = get_data()

    pubkey, privkey = paillier.generate_paillier_keypair(n_length=128)

    encr_X, encr_y = encrypt_matrix(pubkey, X), encrypt_vector(pubkey, y)

    print(encr_y)

    # print('Baseline: compute mean square error of the mean prediction')
    # print("MSE %.2f" % mean_square_error(np.mean(y), y_test))

    # cl = PaillierLinearRegression()
    # cl = cl.fit(X, y)
    # y_pred = cl.predict(X_test)
    # print("MSE %.2f" % mean_square_error(y_pred, y_test))
    # print('For example:')
    # for i in range(5):
    #     print('Predicted %d | Ground truth %d' % (y_pred[i], y_test[i]))



    # print("Generating paillier keypair")
    # alice = Alice()
    # # NOTE: using smaller keys sizes wouldn't be criptographically safe
    # alice.generate_paillier_keypair(n_length=1024)
    #
    # print("\nLearning spam classifier")
    # timer.tick()
    # alice.fit(X, y)
    # timer.tock()
    #
    # print("Classify with model in the clear -- what Alice would get having Bob's data locally")
    # timer.tick()
    # error = np.mean(alice.predict(X_test) != y_test)
    # timer.tock()
    # print("Error %.3f" % error)
    #
    # print("Encrypting classifier")
    # timer.tick()
    # encrypted_weights, encrypted_intercept = alice.encrypt_weights()
    # timer.tock()
    #
    # print("Scoring with encrypted classifier")
    # bob = Bob(alice.get_pubkey())
    # bob.set_weights(encrypted_weights, encrypted_intercept)
    # timer.tick()
    # encrypted_scores = bob.encrypted_evaluate(X_test)
    # timer.tock()
    #
    # print("Decrypt scores and compute error")
    # timer.tick()
    # scores = alice.decrypt_scores(encrypted_scores)
    # error = np.mean(np.sign(scores) != y_test)
    # timer.tock()
    # print("Error %.3f" % error)
