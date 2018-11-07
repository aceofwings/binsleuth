binsleuth
==================

Install system dependencies

.. code-block:: bash

    sudo apt-get install libtiff5-dev libjpeg8-dev zlib1g-dev \
    libfreetype6-dev liblcms2-dev libwebp-dev \
    tcl8.6-dev tk8.6-dev python-tk graphviz

Setting up the project structure
------------------------------------

Install virtualenv. If running a Debian based system use

.. code-block:: bash

    sudo apt install virtualenv


Establish Virtualenv in root directory of repository. You can always structure your
project directory or location as you see fit.

.. code-block:: bash

    mkdir -p ~/project/virtualenvs

    cd ~/project/virtualenvs

    git clone https://github.com/aceofwings/binsleuth.git

    virtualenv -p python3 ~/project/virtualenvs/binsleuth

    #activate the environment

    source ~/project/virtualenvs/binsleuth/bin/activate

Due to some packages being out of date on pypi, directly download them from gitir

.. code-block:: bash

    git clone https://github.com/axt/bingraphvis
    pip install -e ./bingraphvis
    git clone https://github.com/axt/angr-utils
    pip install -e ./angr-utils


Installation
--------------------

Once you have activated the environment, To install the project and dependencies run:

.. code-block:: bash

    python setup.py install

or to develop and softlink the repository, run

.. code-block:: bash

    python setup.py develop

Running
-------------------
Once install test to see if everything is working

.. code-block:: bash

    binsleuth --version
