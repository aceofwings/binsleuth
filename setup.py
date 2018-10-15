import os

try:
    #the standard tools for install package
    from setuptools import setup
    from setuptools import find_packages
    packages = find_packages()
except ImportError:
    #Some versions of python come with setuptools bundled
    from distutils.core import setup
    packages = [x.strip('./').replace('/','.') for x in os.popen('find -name "__init__.py" | xargs -n1 dirname').read().strip().split('\n')]

with open(os.path.join(os.path.dirname(__file__), 'README.rst')) as readme:
    README = readme.read()

# allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

# Put dependencies within the install_requires
# to install the latest add the package name onlyself
# to specify an exact version use == eg. virtualenv==3.0.0
# to specify any version within a minor or major change use ~= eg virtualenv~= 3.5.0
# to specify a package greater then the stated version use <=
install_requires = [
'angr==7.8.8.1',
'pyvex==7.8.8.1',
'cle==7.8.8.1',
'capstone==3.0.5rc2',
'pyelftools==0.24',
'pycparser==2.18',
'cffi==1.11.5',
'angr-utils',
'pyorient',
]

setup(
    name='binsleuth',
    version='0.0.1',
    packages=packages,
    include_package_data=True,
    long_description=README,
    description="Binary Analysis to relate executables using graph like techniques",
    author='Daniel Harrington', #New authors add your name please seperated with a comma
    author_email='dxh7006@rit.edu', # new authors add your work email seperated by a comma
    zip_safe=False,
    classifiers=[
        'Intended Audience :: Malware Specialists',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
    ],
    install_requires = install_requires,
    entry_points ={
      'console_scripts': [
                  'binsleuth = binsleuth.exec:main_func',
              ],
      }
)
