class Attribute:

    def __init__(self):
        self.attributes = []

    def add_attribute(self, attribute_id, value, issuer=None, data_type=None, include_in_result=None):
        attribute = {}
        if attribute_id is not None:
            attribute["AttributeId"] = attribute_id
        if value is not None:
            attribute["Value"] = value
        if issuer is not None:
            attribute["Issuer"] = issuer
        if data_type is not None:
            attribute["DataType"] = data_type
        if include_in_result is not None:
            attribute["IncludeInResult"] = include_in_result
        self.attributes.append(attribute)
