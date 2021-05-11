package myapi.policy
import data.myapi.res
import input

default allow = false

allow {
    m = res.user_ownership[input.sub]
    m[_] == input.res_id
}