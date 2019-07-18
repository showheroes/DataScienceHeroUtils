from setuptools import setup, find_packages

requirements = [req.strip() for req in open("./requirements.txt", "r")]

setup(
    name='adhero_utils',
    version='0.1',
    description='Utility classes for the Showheroes webservice for content collection, information extraction and text classification.',
    author='Patrick Jähnichen',
    author_email='patrick.jaehnichen@showheroes.com',
    package_dir={'':'.'},
    packages=find_packages(where="./"))
