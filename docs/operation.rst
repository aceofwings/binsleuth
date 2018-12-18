===============================
Binsleuth's Operation Structure
===============================

Operations are the core functionality of Bin Sleuth. An operation is a defined as a set of analyzes on a binary.

Operations typically have three responsibilities.

1. Setup functionality based on command line arguments.
2. Run an analysis on some sort of binary file.
3. Return a report objected used within the report engine to further readability  and review results

The operation contains many attributes that can be customized and tailored for whatever analysis you wish to use.
Override the following function, which will be called by the engine

.. code-block:: python

      def run(self):


When an operation finishes the engine will collect data to build a report. This function must return a **ReportObj**

.. code-block:: python

      def report_obj(self):
        Return ReportObj
