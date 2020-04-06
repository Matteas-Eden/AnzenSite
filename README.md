# Anzen 安全
A full-stack project using CherryPy to interact with other similar servers in a peer-to-peer fashion. Created as part of the 2019 iteration of the COMPSYS302 course at the University of Auckland.

## Installation and Operation
1. Clone this repo from the following link: [https://github.com/matteas-eden/anzen](https://github.com/matteas-eden/anzen)
2. Ensure that you have Python3 installed. If you're unsure, simply type `python` in an open terminal. A python console should appear, and it will list the version, e.g. "Python 3.7.3". If it says "Python 2.7.x", then you need to upgrade to Python3.
3. Ensure you have all of the following modules installed:
    * Cherrpy 18.1.1
    * Sqlite3
    * jinja2
    * PyNaCl

You can check for these by opening up a Python3 terminal and running `import cherrypy`, `import sqlite`, etc. If the given module is not installed, you will see an error. You can then install the appropriate module using `pip install`, e.g. `pip install CherryPy`.
You can also run `pip install CherryPy PyNaCl Jinja2`. `sqlite` should be included with your Python installation.
Note: If the above installation does not work, try re-running as `pip3 install CherryPy PyNaCl Jinja2`

4. Once you've checked all the appropriate modules are installed, navigate to the source directory with `cd anzen` and run `python main.py` (this assumes Python3 is your default version, otherwise use `python3`).
5. You should now see a splash message in console, indicating that you have run the server correctly.

Feel to report any issues you find using the "Issues" tab on this repo. Happy messaging!
