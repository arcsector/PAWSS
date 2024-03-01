import os
from setuptools import setup, find_packages

def here(*path):
    return os.path.join(os.path.dirname(__file__), *path)


def get_file_contents(filename):
    with open(here(filename)) as fpo:
        return fpo.read()


long_description = get_file_contents("README.md")

# This is a quick and dirty way to include everything from
# requirements.txt as package dependencies.
install_requires = get_file_contents("requirements.txt").split()

licensetext = get_file_contents("LICENSE")

__version__ = ""
exec(open("shadowapi/_version.py").read())

setup(
	name='pawss',
	description='Python module for interacting with the Shadowserver API',
	long_description=long_description,
    long_description_content_type="text/markdown",
	url='https://github.com/arcsector/pawss',
	author='arcsector',
	author_email='george.r.haraksin@jpl.nasa.gov',
	version=__version__,
	license=licensetext,
	packages=find_packages(exclude=["tests"]),
    python_requires=">=3.6",
	include_package_data=True,
	install_requires=install_requires,
	zip_safe=False
)
