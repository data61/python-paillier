"""
In this example we assume to deal with sensitive data of 442 hospital patients,
with different level of progress of diabetes. Recorded variables are age,
gender, body mass index, average blood pressure, and six blood serum
measurements. A last variable is a quantitative measure of the disease
progression. Since this measure is continuous, we will solve the problem by
linear regression.

The data is distributed in 3 hospitals, referred to as `clients`. The objective
is to make use of the whole (virtual) training set to improve upon the linear
model that can be trained locally. We will keep
50 of the patients as a testset and therefore we will not use them
for training models by any of the hospitals. An additional agent is the
`server`, who will facilitate the information exchange among the hospitals
under the following constrainst. Due to privacy policy:

1) The individual patients' record at each hospital cannot leave its premises,
not even in encrypted form
2) Even aggregated information/summary (read: gradients) of the individual
records cannot leave the hospitals, unless they are first encrypted
3) Not even with knowing the gradients, any of the parties (clients AND server)
must be able to infer WHERE (in which hospital) a patient in the training set
has been treated.

We solve linear regression by gradient descent. The server owns the private
key and the clients own the public key. The protocol works as follows.
Until convergence: hospital 1 computes its gradient, encrypts it and send it to
hospital 2; hospital 2 computes its gradient, encrypts and sums it to
hospital 1's; hospital 3 does the same and passes the overall sum to the
server. The server obtains the full gradient of the whole (virtual) patients
training set; it decrypts it and send it back in the clear to every clients,
who can update their local models.

From the learning viewpoint, keep in mind that we are not assuming that each
hospital sees an unbiased sample from the same patients' distribution:
hospitals could be geographically very distant or serve a diverse population.
We simulate this condition by sampling each patient NOT uniformly at random.
(The test set is instead an unbiased sample from the overall distribution.)

From the security viewpoint, even by seeing the overall gradient in the clear,
nobody among cliens and server can point out where a patient's data is from
inspecting one gradient iteration. This is true if this RING protocol is run by
at least 3 clients, who cannot reconstruct each others gradient simply by
differences.

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
    Import the dataset via sklearn.
    Shuffle and split train/test.
    Return a `n-clients`-size list of train set and one test set
    """

    print("Download data")
    diabetes = load_diabetes()
    y = diabetes.target
    X = diabetes.data

    # Add constant to emulate intercept
    X = np.c_[X, np.ones(X.shape[0])]

    # The features are already preprocessed
    # Shuffle
    perm = np.random.permutation(X.shape[0])
    X, y = X[perm, :], y[perm]

    # Select test at random
    test_size = 50
    test_idx = np.random.choice(X.shape[0], size=test_size, replace=False)
    train_idx = np.ones(X.shape[0], dtype=bool)
    train_idx[test_idx] = False
    X_test, y_test = X[test_idx, :], y[test_idx]
    X_train, y_train = X[train_idx, :], y[train_idx]

    # Split train among multiple clients.
    # The selection is not at random. We simulate the fact that each client
    # sees a potentially very difference sample of patients.
    X, y = [], []
    l = int(X_train.shape[0] / n_clients)
    for c in range(n_clients):
        X.append(X_train[l * c: l * (c + 1), :])
        y.append(y_train[l * c: l * (c + 1)])

    return X, y, X_test, y_test


def mean_square_error(y_pred, y):
    """ 1/m * \sum_{i=1..m} (y_pred_i - y_i)^2 """

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
    """Hold the private key. Decrypt the average gradient"""

    def __init__(self, key_length=1024):
        self.pubkey, self.privkey = \
            paillier.generate_paillier_keypair(n_length=key_length)

    def decrypt_aggregate(self, input_model, n_clients):
        return decrypt_vector(self.privkey, input_model) / n_clients


class Client:
    """Run linear regression either with local data or by gradient steps,
    where gradients can be send from remotely.
    Hold the private key and can encrypt gradients to send remotely.
    """

    def __init__(self, name, X, y, pubkey):
        self.name = name
        self.pubkey = pubkey
        self.X, self.y = X, y
        self.weights = np.zeros(X.shape[1])

    def fit(self, n_iter, eta=0.01):
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

    names = ['Hospital 1', 'Hospital 2', 'Hospital 3']
    n_clients = len(names)

    X, y, X_test, y_test = get_data(n_clients=n_clients)

    # Instantiate the server and generate private and public keys
    server = Server(key_length=1024)

    # We need a baseline to understand how good is any future prediction
    print('Compute a baseline: the mean of all training data')
    for i in range(n_clients):
        print('Baseline at test time:', mean_square_error(np.mean(y[i]), y_test))

    # Instantiate Alice, Bob and Carol.
    # Each client gets the public key at creation and its own local dataset
    clients = []
    for i in range(n_clients):
        clients.append(Client(names[i], X[i], y[i], server.pubkey))

    # Each client trains a linear regressor on its own data
    print('What is the error (MSE) that each client would get on test set by '
          'training only on its own local data?')
    for c in clients:
        c.fit(n_iter=10)
        y_pred = c.predict(X_test)
        print('{:s}:\t{:.2f}'.format(c.name, mean_square_error(y_pred, y_test)))


    # Each client sends its own model to the next one, in a RING protocol,
    # aggregating them all. The last client sends the aggregate model to the server
    # All those exchanges happen the encrypted domain, so neither any client
    # sees in the clear the model of anybody else, nor the server reads any
    # client's individual model.


    # The federated learning with gradient descent
    n_iter = 20
    eta = 0.01
    print('Running distributed gradient aggregation for {:d} iterations'
          .format(n_iter))
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

    # for c in clients:
    #     y_pred = c.predict(c.X)
    #     print(mean_square_error(y_pred, c.y))

    print('What is the error (MSE) that each client after running the secure '
          'protocol?')
    for c in clients:
        y_pred = c.predict(X_test)
        print('{:s}:\t{:.2f}'.format(c.name, mean_square_error(y_pred, y_test)))
