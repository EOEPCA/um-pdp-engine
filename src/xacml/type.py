from enum import Enum

class Decision(Enum):
    PERMIT = "Permit"
    DENY = "Deny"
    INDETERMINATE = "Indeterminate"
    NOTAPPLICABLE = "NotApplicable"
