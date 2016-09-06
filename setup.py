#!/usr/bin/env python

"""
setup.py
"""

from setuptools import setup, find_packages

setup(
    name='ALservice',
    version='2.0.0',
    description='',
    author='DIRG',
    author_email='dirg@its.umu.se',
    license='Apache 2.0',
    url='',
    packages=find_packages('src/'),
    package_dir={'': 'src'},
    package_data={
        'alservice.service': [
            'data/i18n/locales/*/LC_MESSAGES/*.mo',
            'templates/*.mako',
            'site/static/*',
        ],
    },
    classifiers=['Development Status :: 4 - Beta',
                 'License :: OSI Approved :: GNU GENERAL PUBLIC LICENSE',
                 'Topic :: Software Development :: Libraries :: Python Modules',
                 'Programming Language :: Python :: 3.4'],
    install_requires=[
        'pyjwkest',
        'Flask',
        'Flask-Babel',
        'Flask-Mako',
        'dataset <= 0.6.0',
        'gunicorn'
    ],
    zip_safe=False,
    message_extractors={'.': [
        ('src/alservice/**.py', 'python', None),
        ('src/alservice/**/service/templates/**.mako', 'mako', None),
        ('src/alservice/**/service/site/**', 'ignore', None)
    ]}
)
