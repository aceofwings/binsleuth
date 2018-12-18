===============================
Reports Structure
===============================

By default bin sleuth will compile all results into a an html format. The templating is done by the engine known as Jinja.
In order to build your own template for a custom created operation, several things need to be done.

Operation Settings
--------------------------


.. code-block:: python

      operation_name # operation name for which will show up on the report
      obj_name # unique identifier which will be used
      report_template = "template.html" # the name of the template for which will be used to render the report

report template is the the name of the template used to render the report. The framework will automatically find the necessary template within the **templates folder**.

Accessing report object within template context
------------------------------------------------
If you have never used python based template engine please read http://jinja.pocoo.org/docs/2.10/templates/. This engine is popular on most open source frameworks such as Django.

To access the operations report object within the template use the following

.. code-block:: python

       {{report.report_attribute}}

where report_attribute is a desired attribute defined in the ReportObject returned *report_obj* of an operation

for example if the Metadata Report object defines a self attribute **size** then to fetch that value use.

.. code-block:: python

       {{report.size}}

within the report_template set by the metadata operation
