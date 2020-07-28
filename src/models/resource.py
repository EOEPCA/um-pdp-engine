from models.attribute import Attribute

class Resource(Attribute):

    def add_attribute(self, attribute_id, value, data_type, include_in_result):
        super().add_attribute(attribute_id, value, data_type, include_in_result)
