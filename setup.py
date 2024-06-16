from setuptools import setup, find_packages
from os import path

install_requirements = [
    "dataclasses_json>=0.6.6",
    "pytimeparse2>=1.7.1",
    "requests>=2.32.3",
    "setuptools",
]

setup_dir = path.abspath(path.dirname(__file__))

with open(path.join(setup_dir, "README.md")) as file:
    long_description = file.read()

setup(
    name='mchost24',
    version='1.0.0',
    description='A Python Module that allows interacting with the MC-Host24 REST API',
    long_description=long_description,
    long_description_content_type="text/markdown",
    url='https://github.com/JoeJoeTV/mchost24-api-python',
    author='JoeJoeTV',
    author_email='joejoetv@joejoetv.de',
    license='GPL-3.0',
    packages=['mchost24'],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Topic :: Internet",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: System :: Networking",
        "Topic :: Utilities",
    ],
    install_requires=install_requirements,
    zip_safe=False
)