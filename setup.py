
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


def find_version():
    return "1.0"


setup(
    name="phe",
    version=find_version(),
    description="Partially Homomorphic Encryption library for Python",
    long_description=open(os.path.join(here, "README.md")).read(),
    url="https://github.com/NICTA/python-paillier",
    download_url="https://github.com/NICTA/python-paillier/tarball/1.0",
    author="National ICT Australia",
    author_email="brian.thorne@nicta.com.au",
    license="GPLv3",
    classifiers=[
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Natural Language :: English',
        'Topic :: Scientific/Engineering :: Mathematics',
        'Topic :: Security',
        'Topic :: Security :: Cryptography',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
    ],
    keywords="cryptography encryption homomorphic",
    packages=find_packages(exclude=['tests*']),
    entry_points={
        'console_scripts': [
            'pheutil = phe.command_line:cli [CLI]'
        ],
    },
    extras_require={
        'CLI': ['click']
    },
    tests_require=['numpy', 'click'],
    test_suite="phe.tests"
)
