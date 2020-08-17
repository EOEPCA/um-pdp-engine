import json

class Response:
    """
    Header and initiator for the JSON XACML compliant Response class
    """
    def __init__(self,
                 decision: str,
                 obligations_id=None,
                 attr_id=None,
                 value=None,
                 status_code="urn:oasis:names:tc:xacml:1.0:status:ok",
                 data_type="http://www.w3.org/2001/XMLSchema#string"):
        self.Response = [self.ResponseStructure(decision, obligations_id, attr_id, value, status_code, data_type)]

    def __str__(self):
        return json.dumps(self, default=lambda o: o.__dict__, indent=4)


    class ResponseStructure:
        """
        Represents a JSON XACML compliant Response
        """
        def __init__(self,
                    decision: str,
                    obligations_id=None,
                    attr_id=None,
                    value=None,
                    status_code="urn:oasis:names:tc:xacml:1.0:status:ok",
                    data_type="http://www.w3.org/2001/XMLSchema#string"):
            self.Decision = decision
            self.Status = self.Status(self.StatusCode(status_code))
            if (obligations_id is not None or attr_id is not None or value is not None):
                self.Obligations = [self.Obligations(obligations_id, [self.AttributeAssignment(attr_id, value, data_type)])]

        class Status:
            def __init__(self, status_code: object):
                self.StatusCode = status_code

        class StatusCode:
            def __init__(self, value: str):
                self.Value = value

        class Obligations:
            def __init__(self, obligations_id: str, attr_assignment: object):
                self.Id = obligations_id
                self.AttributeAssignment = attr_assignment

        class AttributeAssignment:
            def __init__(self, attr_id: str, value: str, data_type: str):
                self.AttributeId = attr_id
                self.Value = value
                self.DataType = data_type
    

a = Response("Deny", "fail_to_permit", "obligations-id", "You can not access the resource")
b = Response("Permit")
print(a)
print("\n\n")
print(b)