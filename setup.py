from setuptools import setup

setup(
    name = 'Script',
    version = '0.1',
    description = 'Script for formatting log files',
    author = 'Kovalev Victor',
    packages= ['log/eltex-ems/', 
               'log/eltex-portal-constructor/'],
    scripts = ['main.py'],
)
