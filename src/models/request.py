class Request:
    """
    Header and initiator for the JSON XACML compliant Request class
    """
    def __init__(self, subject, action, resource, delegation_addr):
        self.Request = self.RequestStructure(subject, action, resource, delegation_addr)

    class RequestStructure:
        """
        Represents a JSON XACML compliant Request
        """
        def __init__(self, subject: list, action: list, resource: list, delegation_addr: str):
            self.AccessSubject = [self.Attribute(subject)]
            self.IntermediarySubject = [self.Content(delegation_addr)]
            self.Action = [self.Attribute(action)]
            self.Resource = [self.Attribute(resource)]

        class Content:
            def __init__(self, delegation_addr):
                self.Content = delegation_addr

        class Attribute:
            def __init__(self, attr: list):
                self.Attribute = attr
