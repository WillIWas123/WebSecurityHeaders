from setuptools import setup, find_packages

with open("README.md", "r") as f:
    LONG_DESCRIPTION = f.read()

VERSION = "1.0.0"
DESCRIPTION = "Script for checking WebSecurity Headers and reporting autmatically to Sysreptor"

setup(
    name="websecurityheaders",
    version=VERSION,
    author="William/Siddarth",
    author_email="@netsecurity.no",
    description=DESCRIPTION,
    long_description=LONG_DESCRIPTION,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    install_requires=["requests"],
    classifiers=[],
    scripts=["websecurityheaders/websecurityheaders"]

)
