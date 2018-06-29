**************************************************
Infrastructure PenTest Series : Part 5 - Reporting
**************************************************

This blog would explore different open-source reporting tools and data-management tools which can be utilized to during Penetration Test.

Open-Source Reporting Tools
---------------------------

Serpico
^^^^^^^

`Serpico <https://github.com/SerpicoProject/Serpico>`_ : SimplE RePort wrIting and CollaboratiOn tool - Serpico is a penetration testing report generation and collaboration tool. It was developed to cut down on the amount of time it takes to write a penetration testing report. 

Serpico is at its core a report generation tool but targeted at creating information security reports. When building a report the user adds "findings" from the template database to the report. When there are enough findings, click 'Generate Report' to create the docx with your findings. The docx design comes from a Report Template which can be added through the UI; a default one is included. The Report Templates use a custom Markup Language to stub the data from the UI (i.e. findings, customer name, etc) and put them into the report.

DART
^^^^

`DART <https://github.com/lmco/dart/blob/master/README.md>`_ : DART is a test documentation tool created by the Lockheed Martin Red Team to document and report on penetration tests in isolated network environments.

Open-Source Data-Management Tools
---------------------------------

Cisco Kvasir
^^^^^^^^^^^^

`Cisco Kvasir <https://github.com/KvasirSecurity/Kvasir>`_ : Kvasir is a web-based application with its goal to assist “at-a-glance” penetration testing. Disparate information sources such as vulnerability scanners, exploitation frameworks, and other tools are homogenized into a unified database structure. This allows security testers to accurately view the data and make good decisions on the next attack steps. More Information at `Introducing Kvasir <https://blogs.cisco.com/security/introducing-kvasir>`_ 

Threadfix
^^^^^^^^^

`Threadfix <https://github.com/denimgroup/threadfix>`_ : ThreadFix is a software vulnerability aggregation and management system that helps organizations aggregate vulnerability data, generate virtual patches, and interact with software defect tracking systems.

Salesforce Vulnreport
^^^^^^^^^^^^^^^^^^^^^

`SalesForce Vulnreport <https://github.com/salesforce/vulnreport>`_ : Vulnreport is a platform for managing penetration tests and generating well-formatted, actionable findings reports without the normal overhead that takes up security engineer's time. The platform is built to support automation at every stage of the process and allow customization for whatever other systems you use as part of your pentesting process.

Changelog
=========
.. git_changelog::
  :filename_filter: docs/LFF-IPS-P5-Reporting.rst
  :hide_date: false

.. disqus::
