import os
import pytest
from app.main import app, init_db, calculate_discount, DB_NAME


@pytest.fixture
def client():
    if os.path.exists(DB_NAME):
        os.remove(DB_NAME)
    init_db()
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client
    if os.path.exists(DB_NAME):
        os.remove(DB_NAME)


def test_smoke_healthcheck(client):
    res = client.get("/")
    assert res.status_code == 200
    assert res.get_json()["status"] == "ok"


def test_register_success(client):
    res = client.post("/register", json={"username": "newuser", "password": "secret"})
    assert res.status_code == 201


def test_register_short_password(client):
    res = client.post("/register", json={"username": "ab", "password": "12"})
    assert res.status_code == 400


def test_register_duplicate(client):
    res = client.post("/register", json={"username": "student", "password": "password123"})
    assert res.status_code == 409


def test_login_success(client):
    res = client.post("/login", json={"username": "student", "password": "pass123"})
    assert res.status_code == 200
    assert res.get_json()["role"] == "user"


def test_login_wrong_password(client):
    res = client.post("/login", json={"username": "student", "password": "wrong"})
    assert res.status_code == 401


def test_create_note(client):
    client.post("/login", json={"username": "student", "password": "pass123"})
    res = client.post("/notes", json={"title": "Lab 13", "content": "Regression test"})
    assert res.status_code == 201


def test_create_note_unauthorized(client):
    res = client.post("/notes", json={"title": "Hack", "content": "No auth"})
    assert res.status_code == 401


def test_get_and_search_notes(client):
    client.post("/login", json={"username": "student", "password": "pass123"})
    client.post("/notes", json={"title": "Python Pytest", "content": "Automation"})
    res = client.get("/notes/search?q=Pytest")
    assert res.status_code == 200
    assert len(res.get_json()) == 1


def test_rbac_admin_forbidden_for_user(client):
    client.post("/login", json={"username": "student", "password": "pass123"})
    res = client.get("/admin/users")
    assert res.status_code == 403


@pytest.mark.parametrize("price,discount,expected", [
    (1000, 10, 900.0),
    (500, 50, 250.0),
    (200, 0, 200.0),
])
def test_calculate_discount(price, discount, expected):
    assert calculate_discount(price, discount) == expected
