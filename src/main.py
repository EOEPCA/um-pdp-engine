#!/usr/bin/env python3
import time
from policy_storage import Policy_Storage

def main():
    #example rule policy:
    a= {
        "resource_id": "20248583",
        "rules": [{
        "OR": [
                    {"EQUAL": {"user_name" : "mami"} },
                    {"EQUAL": {"user_name" : "admin"} }
        ]
        }]
    }
    #instance
    mongo = Policy_Storage()
    #registrar policy:
    mongo.insert_policy('alvi', 'desc',a,['private'])
    #update policy: (se llama igual, checkea el id y cambia lo que este cambiado)
    #mongo.insert_policy(tuDiccionarioPolicyCambiado)
    #GET segun el id de la policy:
    #n=a.get_policy_from_id(el_id_en_str)
    #GET segun el id del resource asociado
    n=a.get_policy_from_resource_id('20248583')
    #pa borrar, vale cualquier id
    #a.delete_policy(el_id_en_str)
    while True: 
        time.sleep(1000)
if __name__ == "__main__":
    main()