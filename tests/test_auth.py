import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi import status
from models import Base, User
from main import app, init_db, get_db  # Ensure to import your app and any necessary functions
from database import get_db as get_db_dependency

# Setup test database
SQLALCHEMY_DATABASE_URL = "postgresql://postgres:Madhurima%4025@localhost:5432/Modernization"  # Use an in-memory SQLite database for testing
engine = create_engine(SQLALCHEMY_DATABASE_URL,
    pool_size=10,  # Maximum connections in the pool
    max_overflow=5,  # Extra connections if the pool is full
    pool_timeout=30  # Timeout for acquiring connections
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

@pytest.fixture(scope="module")
def db():
    Base.metadata.create_all(bind=engine)  # Create tables
    yield TestingSessionLocal()  # Provide the session to the test
    # Base.metadata.drop_all(bind=engine)  # Clean up after tests

@pytest.fixture(scope="module")
def client(db):
    def override_get_db():
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db_dependency] = override_get_db
    client = TestClient(app)
    init_db()  # Initialize database with a sample user
    return client


def test_create_user(client):
    # Test creating a user
    response = client.post(
        "/users/",
        json={"email": "testuser@example.com", "password": "testpassword", "role": "user"}
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["email"] == "testuser@example.com"


def test_login(client):
    # Test logging in
    response = client.post(
        "/login",
        data={"username": "admin", "password": "admin"}
    )
    assert response.status_code == status.HTTP_200_OK
    assert "access_token" in response.json()
    assert "refresh_token" in response.json()


def test_access_protected_endpoint(client):
    # Log in to get the access token
    login_response = client.post(
        "/login",
        data={"username": "admin", "password": "admin"}
    )
    access_token = login_response.json()["access_token"]

    # Test accessing a protected endpoint
    response = client.get(
        "/admin-data/",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["email"] == "admin"


def test_access_protected_endpoint_without_token(client):
    # Test access to protected endpoint without a token
    response = client.get("/admin-data/")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_create_user_without_permission(client):
    # Log in as a normal user
    login_response = client.post(
        "/login",
        data={"username": "admin", "password": "admin"}
    )
    access_token = login_response.json()["access_token"]

    # Attempt to create a user without admin privileges
    response = client.post(
        "/users/",
        json={"email": "anotheruser1@example.com", "password": "testpassword", "role": "user"},
        headers={"Authorization": f"Bearer {access_token}"}
    )
    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert response.json()["detail"] == "Users can only create users with role 'tester'"


# You can add more tests to cover other functionalities as needed.
