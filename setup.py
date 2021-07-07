from os import path
from setuptools import setup, find_packages

__version__=0.1
setup(
	name='pawss',
	description='Python module for interacting with the Shadowserver API',
	long_description='',
	url='https://github.com/arcsector/PAWSS',
	author='arcsector',
	author_email='george.haraksin@laverne.edu',
	version=__version__,
	license='BSD License',
	packages=find_packages(),
	include_package_data=True,
	install_requires=[
		'requests>=2.18'
	],
	zip_safe=False
)