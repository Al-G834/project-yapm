import pytest
import os
import sys
import json

from project import validate_pwd
from project import read_file
from project import write_file
from project import validate_json
from unittest.mock import Mock, patch, mock_open

#@pytest.fixture(scope='function', autouse=True) 
#def json_error():
#    passwords = {
#  'site 1': {
#      "username": "al", "city": "island",
#    "password": "gAAAAABogboAnBG_2V_3TmHR4wXhtPH_ccwQxS8c3751-9uyF_pRLDQlWBMrrKBny-aLAd8YXxuGmPcMgfPEmWoY85Ucph-iig=="
#    },
#}
    
#    with open("jsonerror.json", "w") as f:
#        json.dump(passwords, f)
#    open(jser, "w")
#    f.write(jser)
#    f.write(jser)

def test_validate_pwd_9char():
    assert validate_pwd("OneFine$1") == True

def test_validate_pwd_embedded_space():
    assert validate_pwd("Not SoFast2!") == False

def test_validate_pwd_illegal_char():
    assert validate_pwd("Not|SoFast2!") == False

def test_validate_pwd_19char():
    assert validate_pwd("1VeryLong#Andpotent") == True

def test_validate_pwd_21char():
    assert validate_pwd("1VeryLong#Andpotent0%") == False

def test_read_file_fnf():
    with pytest.raises(FileNotFoundError) as e_info:
        read_file(json_file="none.json")
    assert str(e_info.value) == "File password.json not found"
    
#def test_read_file_JSONERROR():
#    with pytest.raises(json.JSONDecodeError) as e:
#        my_data = {}
#        my_data ={ '5550 laptop': { 'username': 'Alton Goodman', 'password': 'BigSecret' } }
#        print(f"{my_data}")
#        read_file(json_file=my_data) 
#    assert "JSON Decode error" in str(e)

def test_validate_json_extra_comma():
    def validate_json(json_data =  '''{ "site 1": \
             { "username": "al",, "password": "secret" }}'''):
        try:
            json.loads(json_data)
            return True
        except ValueError as e:
            return False

        with pytest.raises(ValueError) as e:
            str(e) == f"{e}"

def test_validate_json_valid_json():
    assert validate_json('''{ "site 1": \
            { "username": "al", "password": "secret" }}''') == True

