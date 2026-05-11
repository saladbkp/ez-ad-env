#!/usr/bin/env python3
"""
Checker for NoteKeeper service - Hackerdom/ForcAD compatible.

Actions: CHECK, PUT, GET
- CHECK: verify service is up
- PUT: register user, store flag as a note, return username as flag_id
- GET: login as user, verify flag note exists
"""
import sys
import os
import random
import string
import requests
import hashlib

from checklib import *

PORT = 8080


class NoteKeeperChecker(BaseChecker):
    vulns = 1
    timeout = 10
    uses_attack_data = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.base_url = f"http://{self.host}:{PORT}"

    def _rand_string(self, length=12):
        return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))

    def action(self, action, *args, **kwargs):
        try:
            super().action(action, *args, **kwargs)
        except requests.ConnectionError:
            self.cquit(Status.DOWN, "Connection error", "Connection error to service")
        except requests.Timeout:
            self.cquit(Status.DOWN, "Timeout", "Timeout connecting to service")

    def check(self):
        r = requests.get(f"{self.base_url}/health", timeout=5)
        self.assert_eq(r.status_code, 200, "Health check failed")
        data = r.json()
        self.assert_eq(data.get("status"), "ok", "Health check returned wrong status")

        # Also verify basic API works
        r = requests.get(f"{self.base_url}/api/users", timeout=5)
        self.assert_eq(r.status_code, 200, "Users endpoint failed")

        self.cquit(Status.OK)

    def put(self, flag_id: str, flag: str, vuln: int):
        username = self._rand_string(10)
        password = self._rand_string(16)

        # Register
        r = requests.post(
            f"{self.base_url}/api/register",
            json={"username": username, "password": password},
            timeout=5,
        )
        self.assert_eq(r.status_code, 201, "Registration failed")
        data = r.json()
        token = data.get("token", "")
        self.assert_neq(token, "", "No token returned")

        # Store flag as a note
        title = self._rand_string(8)
        r = requests.post(
            f"{self.base_url}/api/notes",
            json={"title": title, "content": flag},
            headers={"X-Token": token},
            timeout=5,
        )
        self.assert_eq(r.status_code, 201, "Note creation failed")
        note_id = r.json().get("id")

        # Save state for GET action
        self.cquit(
            Status.OK,
            username,  # public flag_id (shown in attack data)
            f"{username}:{password}:{token}:{note_id}",  # private data
        )

    def get(self, flag_id: str, flag: str, vuln: int):
        parts = flag_id.split(":")
        if len(parts) != 4:
            self.cquit(Status.CORRUPT, "Bad flag_id format", f"Invalid flag_id: {flag_id}")

        username, password, token, note_id = parts

        # Try to login
        r = requests.post(
            f"{self.base_url}/api/login",
            json={"username": username, "password": password},
            timeout=5,
        )
        self.assert_eq(r.status_code, 200, "Login failed", Status.CORRUPT)
        data = r.json()
        token = data.get("token", "")

        # Retrieve the note
        r = requests.get(
            f"{self.base_url}/api/notes/{note_id}",
            headers={"X-Token": token},
            timeout=5,
        )
        self.assert_eq(r.status_code, 200, "Note retrieval failed", Status.CORRUPT)
        note = r.json()
        self.assert_eq(
            note.get("content"), flag, "Flag mismatch", Status.CORRUPT
        )

        self.cquit(Status.OK)


if __name__ == "__main__":
    c = NoteKeeperChecker(sys.argv[2])
    try:
        c.action(sys.argv[1], *sys.argv[3:])
    except c.get_check_finished_exception():
        cquit(Status(c.status), c.public, c.private)
