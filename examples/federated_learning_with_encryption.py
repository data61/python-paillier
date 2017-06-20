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

import numpy as np
from sklearn.datasets import load_diabetes

import phe as paillier

seed = 42
np.random.seed(seed)


def get_data(n_clients):
    """
    Import the download dataset via sklearn.
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

    # Select test at random
    split = 100
    test_idx = np.random.choice(split, X.shape[0])
    X_test, y_test = X[test_idx, :], y[test_idx]
    X_train, y_train = X[-test_idx, :], y[-test_idx]

    # Split train among multiple clients.
    # The selection is not at random. We simulate the fact that each client.
    # sees a potentially very difference sample of patients.
    X, y = [], []
    l = int(X_train.shape[0] / n_clients)
    np.random.permutation(X_train.shape[0])
    X_train, y_perm = X_train[perm, :], y_train[perm]
    for c in range(n_clients):
        X.append(X_train[l * c: l * (c + 1), :])
        y.append(y_train[l * c: l * (c + 1)])

    return X, y, X_test, y_test


def mean_square_error(y_pred, y):
    """
        1/m * \sum_{i=1..m} (y_pred_i - y_i)^2
    """
    return np.mean((y - y_pred) ** 2)


def encrypt_vector(pubkey, x):
    return [pubkey.encrypt(x[i]) for i in range(x.shape[0])]


def decrypt_vector(privkey, x):
    return np.array([privkey.decrypt(i) for i in x])


def sum_encrypted_vectors(x, y):

    if len(x) != len(y):
        raise Exception('Encrypted vectors must have the same size')

    return [x[i] + y[i]  for i in range(len(x))]


class Server:

    def __init__(self, key_length=1024):
        self.pubkey, self.privkey = \
            paillier.generate_paillier_keypair(n_length=key_length)

    def decrypt_aggregate(self, input_model, n_clients):
        return decrypt_vector(self.privkey, input_model) / n_clients


class Client:

    def __init__(self, name, pubkey):
        self.name = name
        self.pubkey = pubkey

    def fit(self, X, y, n_iter=10, eta=0.01):
        """Linear regression for n_iter. Reset the weights."""

        length, dim = X.shape
        # self.weights = np.zeros(dim)
        #
        # for _ in range(n_iter):
        #     for i in range(length):
        #         delta = self.predict(X[i, :]) - y[i]
        #         for j in range(dim):
        #             self.weights[j] -= eta * delta * X[i, j]
        #
        #     print('Error %.4f' % mean_square_error(self.predict(X), y))

        self.weights = np.linalg.inv(X.T.dot(X)).dot(X.T).dot(y)
        # print(self.weights)

        return self

    # def compute_gradient(self, X, y):
    #     """Return the gradient computed at the current model."""
    #
    #     delta = weights.dot(X[i, :]) - y[i]
    #     return delta * X[i, j]

    def predict(self, X):
        return X.dot(self.weights)
    #
    # def encrypt_and_aggregate(self, input_model=None):
    #
    #     this_model = encrypt_vector(self.pubkey, self.get_model())
    #
    #     if input_model is not None:
    #         return sum_encrypted_vectors(input_model, this_model)
    #     else:
    #         return this_model




# class PaillierLinearRegression():
#
#     def __init__(self, n_iter=60, eta=0.1):
#         self.n_iter = n_iter
#         self.eta = eta
#
#     def fit(self, X, y):
#         length, dim = X.shape
#         weights = np.zeros(dim)
#
#         for _ in range(self.n_iter):
#             for i in range(length):
#                 err = weights.dot(X[i, :]) - y[i]
#                 for j in range(dim):
#                     weights[j] -= self.eta * err * X[i, j]
#
#             self.weights = weights
#             print('Error %.4f' % mean_square_error(self.predict(X), y))
#
#         # self.weights = np.linalg.inv(X.T.dot(X)).dot(X.T).dot(y)
#         # print(self.weights)
#
#         return self
#
#     def fit_encrypted_data(self, X, y):
#         length, dim = len(X), len(X[0])
#         weights = np.zeros(dim)
#
#         for _ in range(self.n_iter):
#             for i in range(length):
#                 err = weights.dot(X[i, :]) - y[i]
#                 for j in range(dim):
#                     weights[j] -= self.eta * err * X[i, j]
#
#             self.weights = weights
#             print('Error %.4f' % mean_square_error(self.predict(X), y))
#
#         # self.weights = np.linalg.inv(X.T.dot(X)).dot(X.T).dot(y)
#         # print(self.weights)
#
#         return self
#
#     def predict(self, X):
#         return X.dot(self.weights)


if __name__ == '__main__':

    n_clients = 3
    X, y, X_test, y_test = get_data(n_clients=1)

    # Instantiate the server and generate private and public keys
    server = Server(key_length=1024)

    # We need a baseline to understand how good is any future prediction
    print('Compute a baseline: the mean of all training data')
    print('Baseline at test time:', mean_square_error(np.mean(y[0]), y_test))

    # Instantiate Alice, Bob and Carol.
    # Each client gets the public key at creation
    clients = []
    clients.append(Client('Alice', server.pubkey))
    clients.append(Client('Bob', server.pubkey))
    clients.append(Client('Carol', server.pubkey))

    c = clients[0]
    c.fit(X[0], y[0], n_iter=60, eta=0.1)
    print('Train', mean_square_error(c.predict(X[0]), y[0]))
    print('Test', mean_square_error(c.predict(X_test), y_test))

    # Each client trains a linear regressor on its own data
    # for (i, c) in enumerate(clients):
    #     c = c.fit(X[i], y[i], n_iter=50, eta=0.05)
    #     print(c.weights)
    #
    # # Predict
    # for (i, c) in enumerate(clients):
    #     print('Train', mean_square_error(c.predict(X[i]), y[i]))
    #     print('Test', mean_square_error(c.predict(X_test), y_test))

    # Each client sends its own model to the next one, in a RING protocol,
    # aggregating them all. The last client sends the aggregate model to the server
    # All those exchanges happen the encrypted domain, so neither any client
    # sees in the clear the model of anybody else, nor the server reads any
    # client's individual model.
    # encrypted_aggr = clients[0].encrypt_and_aggregate(input_model=None)
    # encrypted_aggr = clients[1].encrypt_and_aggregate(input_model=encrypted_aggr)
    # encrypted_aggr = clients[2].encrypt_and_aggregate(input_model=encrypted_aggr)
    # aggr = server.decrypt_aggregate(encrypted_aggr, n_clients)
    # print(aggr)
    # for (i, c) in enumerate(clients):
    #     c.set_model(aggr)
    #     y_pred = c.predict(X_test)
    #     print(mean_square_error(y_pred, y_test))


    # print('Baseline: compute mean square error of the mean prediction')
    # print("MSE %.2f" % mean_square_error(np.mean(y), y_test))

    # cl = PaillierLinearRegression()
    # cl = cl.fit(X, y)
    # y_pred = cl.predict(X_test)
    # print("MSE %.2f" % mean_square_error(y_pred, y_test))
    # print('For example:')
    # for i in range(5):
    #     print('Predicted %d | Ground truth %d' % (y_pred[i], y_test[i]))




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
