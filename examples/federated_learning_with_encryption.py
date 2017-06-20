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


Inspired by Google's work on secure protocol for federated learning
https://research.googleblog.com/2017/04/federated-learning-collaborative.html

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
    test_size = 100
    test_idx = np.random.choice(X.shape[0], size=test_size, replace=False)
    train_idx = np.ones(X.shape[0], dtype=bool)
    train_idx[test_idx] = False
    X_test, y_test = X[test_idx, :], y[test_idx]
    X_train, y_train = X[train_idx, :], y[train_idx]

    # Split train among multiple clients.
    # The selection is not at random. We simulate the fact that each client.
    # sees a potentially very difference sample of patients.
    X, y = [], []
    l = int(X_train.shape[0] / n_clients)
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

    def __init__(self, name, X, y, pubkey):
        self.name = name
        self.pubkey = pubkey
        self.X, self.y = X, y
        self.weights = np.zeros(X.shape[1])

    def fit(self, n_iter, eta):
        """Linear regression for n_iter"""

        for _ in range(n_iter):
            gradient = self.compute_gradient()
            self.gradient_step(gradient, eta)

    def gradient_step(self, gradient, eta=0.01):
        """Update the model with the given gradient"""

        self.weights -= eta * gradient

    def compute_gradient(self):
        """Return the gradient computed at the current model on all training set"""

        delta = self.predict(self.X) - self.y
        return  delta.dot(self.X)

    def predict(self, X):
        """Score test data"""
        return X.dot(self.weights)

    def encrypted_gradient(self, sum_to=None):
        """Compute gradient. Encrypt it.
        When `sum_to` is given, sum the encrypted gradient to it, assumed
        to be another vector of the same size
        """

        gradient = encrypt_vector(self.pubkey, self.compute_gradient())

        if sum_to is not None:
            if len(sum_to) != len(gradient):
                raise Exception('Encrypted vectors must have the same size')
            return sum_encrypted_vectors(sum_to, gradient)
        else:
            return gradient


if __name__ == '__main__':

    names = ['Alice', 'Bob', 'Carol']
    n_clients = len(names)

    X, y, X_test, y_test = get_data(n_clients=n_clients)

    # Instantiate the server and generate private and public keys
    server = Server(key_length=1024)

    # We need a baseline to understand how good is any future prediction
    print('Compute a baseline: the mean of all training data')
    for i in range(n_clients):
        print('Baseline at test time:', mean_square_error(np.mean(y[i]), y_test))

    # Instantiate Alice, Bob and Carol.
    # Each client gets the public key at creation
    clients = []
    for i in range(n_clients):
        clients.append(Client(names[i], X[i], y[i], server.pubkey))

    # Each client trains a linear regressor on its own data


    # Each client sends its own model to the next one, in a RING protocol,
    # aggregating them all. The last client sends the aggregate model to the server
    # All those exchanges happen the encrypted domain, so neither any client
    # sees in the clear the model of anybody else, nor the server reads any
    # client's individual model.


    # The federated learning with gradient from the google paper
    n_iter = 20
    eta = 0.01
    for i in range(n_iter):

        # Compute gradients, encrypt and aggregate
        encrypt_aggr = clients[0].encrypted_gradient(sum_to=None)
        encrypt_aggr = clients[1].encrypted_gradient(sum_to=encrypt_aggr)
        encrypt_aggr = clients[2].encrypted_gradient(sum_to=encrypt_aggr)

        # Send aggregate to server, which decrypts
        aggr = server.decrypt_aggregate(encrypt_aggr, n_clients)

        # Take gradient steps
        for c in clients:
            c.gradient_step(aggr, eta)

    for c in clients:
        y_pred = c.predict(c.X)
        print(mean_square_error(y_pred, c.y))

    for c in clients:
        y_pred = c.predict(X_test)
        print(mean_square_error(y_pred, y_test))
