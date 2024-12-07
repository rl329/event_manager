from builtins import str
import pytest
import uuid
from httpx import AsyncClient
from app.main import app
from app.services.user_service import UserService
from app.models.user_model import User
from app.utils.nickname_gen import generate_nickname
from app.utils.security import hash_password
from app.services.jwt_service import decode_token  # Import your FastAPI app

# Example of a test function using the async_client fixture
@pytest.mark.asyncio
async def test_create_user_access_denied(async_client, user_token, email_service):
    headers = {"Authorization": f"Bearer {user_token}"}
    # Define user data for the test
    user_data = {
        "nickname": generate_nickname(),
        "email": "test@example.com",
        "password": "sS#fdasrongPassword123!",
    }
    # Send a POST request to create a user
    response = await async_client.post("/users/", json=user_data, headers=headers)
    # Asserts
    assert response.status_code == 403

# You can similarly refactor other test functions to use the async_client fixture
@pytest.mark.asyncio
async def test_retrieve_user_access_denied(async_client, verified_user, user_token):
    headers = {"Authorization": f"Bearer {user_token}"}
    response = await async_client.get(f"/users/{verified_user.id}", headers=headers)
    assert response.status_code == 403

@pytest.mark.asyncio
async def test_retrieve_user_access_allowed(async_client, admin_user, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.get(f"/users/{admin_user.id}", headers=headers)
    assert response.status_code == 200
    assert response.json()["id"] == str(admin_user.id)

@pytest.mark.asyncio
async def test_update_user_email_access_denied(async_client, verified_user, user_token):
    updated_data = {"email": f"updated_{verified_user.id}@example.com"}
    headers = {"Authorization": f"Bearer {user_token}"}
    response = await async_client.put(f"/users/{verified_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 403

@pytest.mark.asyncio
async def test_update_user_email_access_allowed(async_client, admin_user, admin_token):
    updated_data = {"email": f"updated_{admin_user.id}@example.com"}
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.put(f"/users/{admin_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 200
    assert response.json()["email"] == updated_data["email"]


@pytest.mark.asyncio
async def test_delete_user(async_client, admin_user, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    delete_response = await async_client.delete(f"/users/{admin_user.id}", headers=headers)
    assert delete_response.status_code == 204
    # Verify the user is deleted
    fetch_response = await async_client.get(f"/users/{admin_user.id}", headers=headers)
    assert fetch_response.status_code == 404

@pytest.mark.asyncio
async def test_create_user_duplicate_email(async_client, verified_user):
    user_data = {
        "email": verified_user.email,
        "password": "AnotherPassword123!",
    }
    response = await async_client.post("/register/", json=user_data)
    assert response.status_code == 400
    assert "Email already exists" in response.json().get("detail", "")

@pytest.mark.asyncio
async def test_create_user_invalid_email(async_client):
    user_data = {
        "email": "notanemail",
        "password": "ValidPassword123!",
    }
    response = await async_client.post("/register/", json=user_data)
    assert response.status_code == 422

import pytest
from app.services.jwt_service import decode_token
from urllib.parse import urlencode

@pytest.mark.asyncio
async def test_login_success(async_client, verified_user):
    # Attempt to login with the test user
    form_data = {
        "username": verified_user.email,
        "password": "MySuperPassword$1234"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})

    # Check for successful login response
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

    # Use the decode_token method from jwt_service to decode the JWT
    decoded_token = decode_token(data["access_token"])
    assert decoded_token is not None, "Failed to decode token"
    assert decoded_token["role"] == "AUTHENTICATED", "The user role should be AUTHENTICATED"

@pytest.mark.asyncio
async def test_login_user_not_found(async_client):
    form_data = {
        "username": "nonexistentuser@here.edu",
        "password": "DoesNotMatter123!"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 401
    assert "Incorrect email or password." in response.json().get("detail", "")

@pytest.mark.asyncio
async def test_login_incorrect_password(async_client, verified_user):
    form_data = {
        "username": verified_user.email,
        "password": "IncorrectPassword123!"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 401
    assert "Incorrect email or password." in response.json().get("detail", "")

@pytest.mark.asyncio
async def test_login_unverified_user(async_client, unverified_user):
    form_data = {
        "username": unverified_user.email,
        "password": "MySuperPassword$1234"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 401

@pytest.mark.asyncio
async def test_login_locked_user(async_client, locked_user):
    form_data = {
        "username": locked_user.email,
        "password": "MySuperPassword$1234"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 400
    assert "Account locked due to too many failed login attempts." in response.json().get("detail", "")
@pytest.mark.asyncio
async def test_delete_user_does_not_exist(async_client, admin_token):
    non_existent_user_id = "00000000-0000-0000-0000-000000000000"  # Valid UUID format
    headers = {"Authorization": f"Bearer {admin_token}"}
    delete_response = await async_client.delete(f"/users/{non_existent_user_id}", headers=headers)
    assert delete_response.status_code == 404

@pytest.mark.asyncio
async def test_update_user_github(async_client, admin_user, admin_token):
    updated_data = {"github_profile_url": "http://www.github.com/kaw393939"}
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.put(f"/users/{admin_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 200
    assert response.json()["github_profile_url"] == updated_data["github_profile_url"]

@pytest.mark.asyncio
async def test_update_user_linkedin(async_client, admin_user, admin_token):
    updated_data = {"linkedin_profile_url": "http://www.linkedin.com/kaw393939"}
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.put(f"/users/{admin_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 200
    assert response.json()["linkedin_profile_url"] == updated_data["linkedin_profile_url"]

@pytest.mark.asyncio
async def test_list_users_as_admin(async_client, admin_token):
    response = await async_client.get(
        "/users/",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 200
    assert 'items' in response.json()

@pytest.mark.asyncio
async def test_list_users_as_manager(async_client, manager_token):
    response = await async_client.get(
        "/users/",
        headers={"Authorization": f"Bearer {manager_token}"}
    )
    assert response.status_code == 200

@pytest.mark.asyncio
async def test_list_users_unauthorized(async_client, user_token):
    response = await async_client.get(
        "/users/",
        headers={"Authorization": f"Bearer {user_token}"}
    )
    assert response.status_code == 403  # Forbidden, as expected for regular user

@pytest.mark.asyncio
async def test_update_user_invalid_data(async_client, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    invalid_data = {"email": "not-an-email"}
    response = await async_client.put("/users/valid-user-id", json=invalid_data, headers=headers)
    assert response.status_code == 422  # Unprocessable Entity

@pytest.mark.asyncio
async def test_get_user_not_found(async_client, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    invalid_user_id = str(uuid.uuid4())  # Generate a valid UUID
    response = await async_client.get(f"/users/{invalid_user_id}", headers=headers)
    assert response.status_code == 404
    assert response.json()["detail"] == "User not found"

@pytest.mark.asyncio
async def test_delete_user_not_found(async_client, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    invalid_user_id = str(uuid.uuid4())  # Generate a valid UUID
    response = await async_client.delete(f"/users/{invalid_user_id}", headers=headers)
    assert response.status_code == 404
    assert response.json()["detail"] == "User not found"

@pytest.mark.asyncio
async def test_verify_email_invalid_token(async_client, admin_token):
    invalid_user_id = str(uuid.uuid4())
    response = await async_client.get(f"/verify-email/{invalid_user_id}/invalid-token")
    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid or expired verification token"

@pytest.mark.asyncio
async def test_verify_email_with_invalid_token(db_session, unverified_user):
    invalid_token = "fake-token"
    result = await UserService.verify_email_with_token(db_session, unverified_user.id, invalid_token)
    assert result is False, "Verification with an invalid token should return False"

@pytest.mark.asyncio
async def test_unlock_user_account_already_unlocked(db_session, verified_user):
    result = await UserService.unlock_user_account(db_session, verified_user.id)
    assert result is False, "Unlocking an already unlocked user should return False"

@pytest.mark.asyncio
async def test_reset_password_nonexistent_user(db_session):
    fake_user_id = uuid.uuid4()
    result = await UserService.reset_password(db_session, fake_user_id, "NewPassword123!")
    assert result is False, "Resetting password for a nonexistent user should return False"

@pytest.mark.asyncio
async def test_delete_nonexistent_user(db_session):
    fake_user_id = uuid.uuid4()
    result = await UserService.delete(db_session, fake_user_id)
    assert result is False, "Deleting a nonexistent user should return False"

@pytest.mark.asyncio
async def test_update_user_not_found(async_client, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    updated_data = {"email": "updated@example.com"}
    non_existent_user_id = "00000000-0000-0000-0000-000000000000"

    response = await async_client.put(f"/users/{non_existent_user_id}", json=updated_data, headers=headers)
    assert response.status_code == 404
    assert response.json()["detail"] == "User not found"

@pytest.mark.asyncio
async def test_delete_user_access_denied(async_client, user_token):
    headers = {"Authorization": f"Bearer {user_token}"}
    target_user_id = "00000000-0000-0000-0000-000000000000"

    response = await async_client.delete(f"/users/{target_user_id}", headers=headers)
    assert response.status_code == 403

@pytest.mark.asyncio
async def test_list_users_unauthorized(async_client):
    response = await async_client.get("/users/")
    assert response.status_code == 401  # Unauthorized, no token provided

@pytest.mark.asyncio
async def test_register_user_duplicate_email(async_client, verified_user):
    user_data = {
        "email": verified_user.email,
        "password": "AnotherPassword123!"
    }
    response = await async_client.post("/register/", json=user_data)
    assert response.status_code == 400
    assert "Email already exists" in response.json()["detail"]

@pytest.mark.asyncio
async def test_verify_email_invalid_token(async_client):
    invalid_user_id = str(uuid.uuid4())
    response = await async_client.get(f"/verify-email/{invalid_user_id}/invalid-token")
    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid or expired verification token"

@pytest.mark.asyncio
async def test_login_account_locked(async_client, locked_user):
    form_data = {
        "username": locked_user.email,
        "password": "MySuperPassword$1234"
    }
    response = await async_client.post(
        "/login/", data=form_data, headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    assert response.status_code == 400
    assert "Account locked due to too many failed login attempts." in response.json()["detail"]

@pytest.mark.asyncio
async def test_login_user_not_found(async_client):
    form_data = {
        "username": "nonexistentuser@domain.com",
        "password": "DoesNotMatter123!"
    }
    response = await async_client.post(
        "/login/", data=form_data, headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    assert response.status_code == 401
    assert "Incorrect email or password." in response.json()["detail"]

@pytest.mark.asyncio
async def test_get_user_not_found(async_client, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    invalid_user_id = str(uuid.uuid4())

    response = await async_client.get(f"/users/{invalid_user_id}", headers=headers)
    assert response.status_code == 404
    assert response.json()["detail"] == "User not found"

@pytest.mark.asyncio
async def test_update_user_invalid_data(async_client, admin_user, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    invalid_data = {"email": "not-an-email"}

    response = await async_client.put(f"/users/{admin_user.id}", json=invalid_data, headers=headers)
    assert response.status_code == 422  # Unprocessable Entity

@pytest.mark.asyncio
async def test_delete_user_already_deleted(async_client, admin_user, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}

    # First, delete the user
    delete_response = await async_client.delete(f"/users/{admin_user.id}", headers=headers)
    assert delete_response.status_code == 204

    # Attempt to delete again
    delete_response_again = await async_client.delete(f"/users/{admin_user.id}", headers=headers)
    assert delete_response_again.status_code == 404
    assert delete_response_again.json()["detail"] == "User not found"

@pytest.mark.asyncio
async def test_get_user_unauthorized_access(async_client, user_token):
    headers = {"Authorization": f"Bearer {user_token}"}
    user_id = str(uuid.uuid4())  # Random user UUID
    response = await async_client.get(f"/users/{user_id}", headers=headers)

    assert response.status_code == 403
    # Adjust assertion to handle both expected messages
    assert response.json()["detail"] in ["Access forbidden for your role", "Operation not permitted"]

@pytest.mark.asyncio
async def test_delete_user_access_unauthorized(async_client, user_token):
    invalid_headers = {"Authorization": f"Bearer {user_token}"}
    user_id = "00000000-0000-0000-0000-000000000000"
    response = await async_client.delete(f"/users/{user_id}", headers=invalid_headers)
    assert response.status_code == 403

@pytest.mark.asyncio
async def test_create_user_missing_fields(async_client, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    incomplete_user_data = {
        "email": "incomplete@example.com"  # Missing required fields like `password`
    }
    response = await async_client.post("/users/", json=incomplete_user_data, headers=headers)
    assert response.status_code == 422  # Unprocessable Entity

@pytest.mark.asyncio
async def test_update_user_invalid_input(async_client, admin_user, admin_token):
    invalid_data = {"email": "invalid-email-format"}
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.put(f"/users/{admin_user.id}", json=invalid_data, headers=headers)
    assert response.status_code == 422

@pytest.mark.asyncio
async def test_verify_email_missing_token(async_client):
    user_id = "00000000-0000-0000-0000-000000000000"
    response = await async_client.get(f"/verify-email/{user_id}/")
    assert response.status_code == 404  # FastAPI will raise 404 for missing route params

@pytest.mark.asyncio
async def test_get_user_invalid_id(async_client, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    invalid_user_id = "invalid-uuid"
    response = await async_client.get(f"/users/{invalid_user_id}", headers=headers)
    assert response.status_code == 422

@pytest.mark.asyncio
async def test_create_user_missing_fields(async_client, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    incomplete_user_data = {"email": "missingpassword@example.com"}
    response = await async_client.post("/users/", json=incomplete_user_data, headers=headers)
    assert response.status_code == 422

@pytest.mark.asyncio
async def test_list_users_pagination_edge_cases(async_client, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Case: skip beyond available users
    response = await async_client.get("/users/?skip=1000&limit=10", headers=headers)
    assert response.status_code == 200
    assert response.json()["items"] == []

    # Case: limit=0 (no users returned)
    response = await async_client.get("/users/?skip=0&limit=0", headers=headers)
    assert response.status_code == 200
    assert response.json()["items"] == []

@pytest.mark.asyncio
async def test_create_user_duplicate_email(async_client, verified_user):
    user_data = {
        "email": verified_user.email,
        "password": "AnotherPassword123!"
    }
    response = await async_client.post("/register/", json=user_data)

    # Assertions
    assert response.status_code == 400
    assert "Email already exists" in response.json().get("detail", "")
