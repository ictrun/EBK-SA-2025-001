# Uncontrolled Recursion in JSON/XML Parsing Leading to Denial of Service
## Summary

ezBookkeeping versions 1.2.0 and earlier contain a critical vulnerability in JSON and XML file import processing. The application fails to validate nesting depth during parsing operations, allowing authenticated attackers to trigger denial of service conditions by uploading deeply nested malicious files. This results in CPU exhaustion, service degradation, or complete service unavailability.
