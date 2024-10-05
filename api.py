#!/usr/bin/env python
# -*- coding: utf-8 -*-

import datetime
import hashlib
import json
import logging
import re
import uuid
from abc import ABC
from argparse import ArgumentParser
from http.server import BaseHTTPRequestHandler, HTTPServer

from scoring import get_interests, get_score

SALT = "Otus"
ADMIN_LOGIN = "admin"
ADMIN_SALT = "42"
OK = 200
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
INVALID_REQUEST = 422
INTERNAL_ERROR = 500
ERRORS = {
    BAD_REQUEST: "Bad Request",
    FORBIDDEN: "Forbidden",
    NOT_FOUND: "Not Found",
    INVALID_REQUEST: "Invalid Request",
    INTERNAL_ERROR: "Internal Server Error",
}
UNKNOWN = 0
MALE = 1
FEMALE = 2
GENDERS = {
    UNKNOWN: "unknown",
    MALE: "male",
    FEMALE: "female",
}
MAX_AGE = 70


class Field(ABC):
    def __init__(self, name, required=False, nullable=True):
        self.name = name
        self.required = required
        self.nullable = nullable

    def validate(self, value):
        raise NotImplementedError("You should implement this method in subclasses.")


class CharField(Field):
    def validate(self, value):
        if self.required and value is None:
            raise ValueError(f"Field '{self.name}' is required but not provided.")
        if not self.nullable and value is None:
            raise ValueError(f"Field '{self.name}' cannot be null.")
        if value and not isinstance(value, str):
            raise ValueError(f"Field '{self.name}' value must be a string.")


class IntField(Field):
    def validate(self, value):
        if self.required and value is None:
            raise ValueError(f"Field '{self.name}' is required but not provided.")
        if not self.nullable and value is None:
            raise ValueError(f"Field '{self.name}' cannot be null.")
        if value and not isinstance(value, int):
            raise ValueError(f"Field '{self.name}' value must be an integer.")


class EmailField(CharField):
    def validate(self, value):
        super().validate(value)
        if value and not re.match(r"[^@]+@[^@]+\.[^@]+", value):
            raise ValueError(f"Field '{self.name}' has an invalid email format.")

class PhoneField(Field):

    def validate(self, value):
        if self.required:
            if not isinstance(value, (str, int)):
                raise ValueError(f"Field '{self.name}' must be a string or a number.")
            value_str = str(value)
            if len(value_str) != 11 or not value_str.startswith("7"):
                raise ValueError(f"Field '{self.name}' must be 11 characters long and start with '7'.")


class DateField(CharField):

    def validate(self, value):
        super().validate(value)
        if value:
            datetime.datetime.strptime(value, "%d.%m.%Y")


class BirthDayField(DateField):

    @staticmethod
    def get_age(dob):
        today = datetime.date.today()
        years = today.year - dob.year
        if today.month < dob.month or (today.month == dob.month and today.day < dob.day):
            years -= 1
        return years

    def validate(self, value):
        super().validate(value)
        if value:
            birthdate = datetime.datetime.strptime(value, "%d.%m.%Y")
            age = self.get_age(birthdate)
            if age > MAX_AGE:
                raise ValueError(f"Field '{self.name}' cannot be older than 70 years.")


class GenderField(IntField):
    def validate(self, value):
        super().validate(value)
        if value and value not in [UNKNOWN, MALE, FEMALE]:
            raise ValueError(f"Field '{self.name}' has invalid value.")


class ClientIDsField(Field):
    def validate(self, value):
        if self.required and not value:
            raise ValueError(f"Field '{self.name}' is required but not provided.")
        if not self.nullable and not value:
            raise ValueError(f"Field '{self.name}' cannot be null.")
        if self.required and not isinstance(value, list):
            raise ValueError(f"Field '{self.name}' value must be a list.")
        if value and not all(isinstance(v, int) for v in value):
            raise ValueError(f"Field '{self.name}' value must be a list of integers.")


class ArgumentsField(Field):
    def validate(self, value):
        if value is None:
            if self.required:
                raise ValueError(f"Field '{self.name}' is required but not provided.")
        if not isinstance(value, dict):
            raise ValueError(f"Field '{self.name}' must be a dictionary (JSON object).")


class Request:
    def validate_fields(self):
        for field_name, field_type in self.__class__.__dict__.items():
            if isinstance(field_type, Field):
                value = getattr(self, field_name)
                field_type.validate(value)


class ClientsInterestsRequest(Request):
    client_ids = ClientIDsField(name="client_ids", required=True, nullable=False)
    date = DateField(name="date", required=False, nullable=True)

    def __init__(self, client_ids=None, date=None):
        self.client_ids = client_ids
        self.date = date

    @staticmethod
    def get_intersts(store, cids):
        res = {}
        for cid in cids:
            res[cid] = get_interests(store, cid)
        return res


class OnlineScoreRequest(Request):
    first_name = CharField(name="first_name", required=False, nullable=True)
    last_name = CharField(name="last_name", required=False, nullable=True)
    email = EmailField(name="email", required=False, nullable=True)
    phone = PhoneField(name="phone", required=False, nullable=True)
    birthday = BirthDayField(name="birthday", required=False, nullable=True)
    gender = GenderField(name="gender", required=False, nullable=True)

    def __init__(
        self,
        first_name=None,
        last_name=None,
        email=None,
        phone=None,
        birthday=None,
        gender=None,
    ):
        self.first_name = first_name
        self.last_name = last_name
        self.email = email
        self.phone = phone
        self.birthday = birthday
        self.gender = gender

    def validate_fields(self):
        super().validate_fields()
        if not (
            (self.phone is not None and self.email is not None)
            or (self.first_name is not None and self.last_name is not None)
            or (self.gender is not None and self.birthday is not None)
        ):
            raise ValueError("At least one pair phone-email, first name-last name, gender-birthday is required.")

    def get_score(self, store):
        return {
            "score": get_score(
                store,
                phone=self.phone,
                email=self.email,
                birthday=self.birthday,
                gender=self.gender,
                first_name=self.first_name,
                last_name=self.last_name,
            )
        }


class MethodRequest(Request):
    account = CharField(name="account", required=False, nullable=True)
    login = CharField(name="login", required=True, nullable=True)
    token = CharField(name="token", required=True, nullable=True)
    arguments = ArgumentsField(name="arguments", required=True, nullable=True)
    method = CharField(name="method", required=True, nullable=False)

    def __init__(self, account=None, login=None, token=None, arguments=None, method=None):
        self.account = account
        self.login = login
        self.token = token
        self.arguments = arguments
        self.method = method

    def validate_fields(self):
        super().validate_fields()

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN


def check_auth(request):
    if request.is_admin:
        digest = hashlib.sha512((datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT).encode("utf-8")).hexdigest()
    else:
        digest = hashlib.sha512((request.account + request.login + SALT).encode("utf-8")).hexdigest()
    return digest == request.token


def method_handler(request, ctx, store):
    request = MethodRequest(**request["body"])
    try:
        request.validate_fields()
    except Exception as ex:
        logging.info(f"request invalid with exception: {ex}")
        return str(ex), INVALID_REQUEST

    if not check_auth(request):
        logging.info("request forbidden")
        return ERRORS[FORBIDDEN], FORBIDDEN

    if request.method == "clients_interests":
        scoring_request = ClientsInterestsRequest(**request.arguments)
        try:
            scoring_request.validate_fields()
        except Exception as ex:
            logging.info(f"clients_interests request invalid with exception: {ex}")
            return str(ex), INVALID_REQUEST

        logging.info("clients_interests request successful")
        score = scoring_request.get_intersts(store, scoring_request.client_ids)
        return score, OK
    else:
        scoring_request = OnlineScoreRequest(**request.arguments)
        try:
            scoring_request.validate_fields()
        except Exception as ex:
            logging.info(f"Scoring request invalid with exception: {ex}")
            return str(ex), INVALID_REQUEST
        score = scoring_request.get_score(store)
        logging.info("Scoring request successful")
        return score, OK


class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {"method": method_handler}
    store = None

    def get_request_id(self, headers):
        return headers.get("HTTP_X_REQUEST_ID", uuid.uuid4().hex)

    def do_POST(self):
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}
        request = None
        try:
            data_string = self.rfile.read(int(self.headers["Content-Length"]))
            request = json.loads(data_string)
        except:
            code = BAD_REQUEST

        if request:
            path = self.path.strip("/")
            logging.info("%s: %s %s" % (self.path, data_string, context["request_id"]))
            if path in self.router:
                try:
                    response, code = self.router[path]({"body": request, "headers": self.headers}, context, self.store)
                except Exception as e:
                    logging.exception("Unexpected error: %s" % e)
                    code = INTERNAL_ERROR
            else:
                code = NOT_FOUND

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if code not in ERRORS:
            r = {"response": response, "code": code}
        else:
            r = {"error": response or ERRORS.get(code, "Unknown Error"), "code": code}
        context.update(r)
        logging.info(context)
        self.wfile.write(json.dumps(r).encode("utf-8"))
        return


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("-p", "--port", action="store", type=int, default=8080)
    parser.add_argument("-l", "--log", action="store", default=None)
    args = parser.parse_args()
    logging.basicConfig(
        filename=args.log,
        level=logging.INFO,
        format="[%(asctime)s] %(levelname).1s %(message)s",
        datefmt="%Y.%m.%d %H:%M:%S",
    )
    server = HTTPServer(("localhost", args.port), MainHTTPHandler)
    logging.info("Starting server at %s" % args.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
