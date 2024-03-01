import json
from typing import TypedDict
import requests

URL = "https://interchange.shadowserver.org/schema/reports.json"
CLASS = """class {name}:
{docstring}
    {fields}

"""
DOCSTRING = """    '''Representation of report {name} with type {type} and taxonomy {taxonomy}

        For more information, visit {url}
        
    Attributes:
        {fieldslist}
    '''"""
FIELD = "{field} (Any): Report attribute {field}"
ATTRS = "{field}: Any"

def fieldsfilter(name: str) -> str:
    if name in ["class"]:
        return ""
    return name

reportsjson = requests.get(URL, timeout=10).text
reportsdict = json.loads(reportsjson)
# We expect this to be a flat file with keys as names of the reports
# and fields like such:

ReportsSchemaSpec = TypedDict("ReportsSchemaSpec", {
    "classification.taxonomy": str,
    "classification.type": str,
    "fields": list[str],
    "name": str,
    "url": str
})

classes = ['from typing import Any\n']

for reporttype, details in reportsdict.items():
    details: ReportsSchemaSpec
    reporttype: str
    #print(reporttype + ": " + details['name'])
    classname = reporttype.replace('_', ' ').title().replace(' ', '')
    docname = details['name']
    fields = details['fields']
    typ = details.get('classification.type', 'undetermined')
    tax = details.get('classification.taxonomy', 'other')
    url = details.get('url', 'unknown')
    fieldlist = [FIELD.format(field=i) for i in fields]
    pyattrlist = [ATTRS.format(field=i) for i in fields if fieldsfilter(i)]
    docstr = DOCSTRING.format(
        name=docname,
        type=typ,
        taxonomy=tax,
        url=url,
        fieldslist='\n        '.join(fieldlist)
    )
    classdef = CLASS.format(
        name=classname,
        docstring=docstr,
        fields='\n    '.join(pyattrlist)
    )
    classes.append(classdef)

open('report_models.py', 'w+', encoding='ascii').writelines(classes)
