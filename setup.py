#!/usr/bin/env python

"""
setup.py
"""

from setuptools import setup, find_packages

setup(
    name='ALservice',
    version='1.0.0',
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
    install_requires=["pyjwkest", "Flask", "Flask-Babel", "Flask-Mako", "dataset"],
    zip_safe=False,
)
