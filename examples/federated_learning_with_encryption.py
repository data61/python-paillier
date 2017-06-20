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
    # np.random.permutation(X_train.shape[0])
    # X_train, y_perm = X_train[perm, :], y_train[perm]
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
        self.X = X
        self.y = y

        self.dim = X.shape[1]
        self.weights = np.zeros(self.dim)

    def fit(self, n_iter=10, eta=0.01):
        """Linear regression for n_iter"""

        length = self.X.shape[0]

        for _ in range(n_iter):
            for i in range(length):
                delta = self.predict(self.X[i, :]) - self.y[i]
                for j in range(self.dim):
                    self.weights[j] -= eta * delta * self.X[i, j]

            # print('Error %.4f' % mean_square_error(self.predict(X), y))

        # self.weights = np.linalg.inv(X.T.dot(X)).dot(X.T).dot(y)
        # print(self.weights)

        return self

    def gradient_step(self, gradient, eta=0.01):
        """Update the model with the given gradient"""

        for j in range(self.dim):
            self.weights[j] -= eta * gradient[j]


    def compute_gradient(self):
        """Return the gradient computed at the current model on all training set"""

        gradient = np.zeros(self.dim)
        for i in range(self.X.shape[0]):
            delta = self.predict(self.X[i, :]) - self.y[i]
            for j in range(self.dim):
                gradient += delta * self.X[i, j]
        return gradient

    def predict(self, X):
        """Score test data"""
        return X.dot(self.weights)

    def encrypt_and_aggregate(self, input_model=None):

        this_model = encrypt_vector(self.pubkey, self.weights)

        if input_model is not None:
            return sum_encrypted_vectors(input_model, this_model)
        else:
            return this_model

    def encrypted_gradient(self, sum_to=None):

        gradient = encrypt_vector(self.pubkey, self.compute_gradient())

        if sum_to is not None:
            return sum_encrypted_vectors(sum_to, gradient)
        else:
            return gradient


if __name__ == '__main__':

    n_clients = 3
    names = ['Alice', 'Bob', 'Carol']
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
    # for (i, c) in enumerate(clients):
    #     c = c.fit(n_iter=50, eta=0.05)
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
    #     c.weights = aggr
    #     y_pred = c.predict(X_test)
    #     print(mean_square_error(y_pred, y_test))

    # The federated learning with gradient from the google paper
    n_iter = 5
    for i in range(n_iter):

        # Compute gradients, encrypt and aggregate
        encrypt_aggr = clients[0].encrypted_gradient(sum_to=None)
        encrypt_aggr = clients[1].encrypted_gradient(sum_to=encrypt_aggr)
        encrypt_aggr = clients[2].encrypted_gradient(sum_to=encrypt_aggr)

        # Send aggregate to server, which decrypts
        aggr = server.decrypt_aggregate(encrypt_aggr, n_clients)

        # Take gradient steps
        clients[0].gradient_step(aggr)
        clients[1].gradient_step(aggr)
        clients[2].gradient_step(aggr)

    for (i, c) in enumerate(clients):
        y_pred = c.predict(c.X)
        print(mean_square_error(y_pred, c.y))

    for (i, c) in enumerate(clients):
        y_pred = c.predict(X_test)
        print(mean_square_error(y_pred, y_test))
