#!/usr/bin/env python

"""
setup.py
"""

from setuptools import setup, find_packages

setup(
    name='ALservice',
    version='0.0.1',
    description='',
    author='DIRG',
    author_email='dirg@its.umu.se',
    license='GNU GENERAL PUBLIC LICENSE V 3',
    url='',
    packages=find_packages('src/'),
    package_dir={'': 'src'},
    classifiers=['Development Status :: 4 - Beta',
                 'License :: OSI Approved :: GNU GENERAL PUBLIC LICENSE',
                 'Topic :: Software Development :: Libraries :: Python Modules',
                 'Programming Language :: Python :: 3.4'],
    install_requires=["pyjwkest"],
    zip_safe=False,
)
