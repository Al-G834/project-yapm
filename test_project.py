import pytest
import os
import sys
from project import validate_pwd
from project import read_file
from project import write_file
from project import validate_json
from project import update_password
import json

@pytest.mark.parametrize(("password, expected"),
        [
            pytest.param("OneFine$1", True, id="9 Char Valid Passowrd"),
            pytest.param("2Short!", False, id="7 Char Invalid Passowrd"),
            pytest.param("1VeryLong#Andpotent", True, id="19 Characters"),
            pytest.param("1PwdJustLongenough&!", True, id="20 Characters"),
            pytest.param("1TooLong@#Andpotent0%", False, id="21 Characters"),
            pytest.param("Not SoFast2!", False, id="Embedded space"),
            pytest.param("Not|SoFast2!", False, id="Illegal character"),
            ],
        )
def test_validate_pwd(password, expected):
    assert validate_pwd(password) == expected

def test_read_file_fnf():
    with pytest.raises(FileNotFoundError) as e_info:
        read_file(json_file="none.json")
    assert str(e_info.value) == "File password.json not found"

@pytest.fixture
def bad_json(tmp_path):
    my_data ={ '5550 laptop': { 1: 'Alton Goodman', 'password': 'BigSecret' } }
    target = os.path.join(tmp_path, "password.json")
    with open(target, "w", encoding="utf-8") as f:
        f.write(str(my_data))
    return target

def test_read_file_JSONDECODE_ERROR(bad_json):
    with pytest.raises(json.JSONDecodeError) as e_info:
        read_file(bad_json)
    assert str(e_info.value) == "Invalid JSON syntax: line 1 column 1 (char 0)"


@pytest.mark.parametrize(
        ("site, password, password_dict, expected_exception"),
        [
            ('site 1', 'TooEasy#2', \
                    '{ "site 1": \
                    { "username": "al", "password": 1 }}', TypeError,
                    ),
            ],
        )
def test_update_password(site, password, password_dict, expected_exception):
    with pytest.raises(TypeError):
        update_password(site, password, password_dict)
    
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

