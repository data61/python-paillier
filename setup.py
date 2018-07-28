
# This file is part of python-paillier.
#
# python-paillier is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# python-paillier is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with python-paillier.  If not, see <http://www.gnu.org/licenses/>.

import os
from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))

about = {}
with open(os.path.join(here, "phe", "__about__.py")) as f:
    exec(f.read(), about)


setup(
    name=about['__title__'],
    version=about['__version__'],
    description=about['__summary__'],
    long_description=open(os.path.join(here, "README.rst")).read(),
    url=about['__uri__'],
    download_url="https://pypi.python.org/pypi/phe/#downloads",
    author=about['__author__'],
    author_email=about['__email__'],
    license=about['__license__'],
    classifiers=[
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Natural Language :: English',
        'Topic :: Scientific/Engineering :: Mathematics',
        'Topic :: Security',
        'Topic :: Security :: Cryptography',
        'Intended Audience :: Science/Research',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7'
    ],
    keywords="cryptography encryption homomorphic",
    packages=find_packages(exclude=['tests*']),
    entry_points={
        'console_scripts': [
            'pheutil = phe.command_line:cli [cli]'
        ],
    },
    extras_require={
        'cli': ['click'],
        'examples': ['numpy', 'scipy', 'sklearn']
    },
    install_requires=[],
    tests_require=['click', 'gmpy2', 'numpy'],
    test_suite="phe.tests"
)
