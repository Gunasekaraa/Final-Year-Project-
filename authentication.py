import requests
import streamlit as st

API_BASE_URL = "http://127.0.0.1:8000/api"

def signup(username, email, password):
    """
    Register a new user by sending a signup request to the Django backend.
    
    Args:
        username (str): The username for the new user.
        email (str): The email for the new user.
        password (str): The password for the new user.
    
    Returns:
        bool: True if signup is successful, False otherwise.
    
    Raises:
        requests.RequestException: If there's a network error.
    """
    response = requests.post(
        f"{API_BASE_URL}/register/",
        json={
            "username": username,
            "email": email,
            "password": password
        },
        headers={"Content-Type": "application/json"}
    )
    return response.status_code == 201

def login(username, password):
    """
    Authenticate a user by sending a login request to the Django backend.
    
    Args:
        username (str): The username to authenticate.
        password (str): The password to authenticate.
    
    Returns:
        dict or None: A dictionary containing user data (e.g., {"email": "...", "token": "..."}) if successful,
                      None if login fails.
    
    Raises:
        requests.RequestException: If there's a network error.
    """
    try:
        response = requests.post(
            f"{API_BASE_URL}/login/",
            json={"username": username, "password": password},
            headers={"Content-Type": "application/json"}
        )
        print(f"Login API Response Status: {response.status_code}")
        print(f"Login API Response: {response.json()}")
        
        if response.status_code == 200:
            data = response.json()
            token = data.get("token", {}).get("access")
            email = data.get("email")  # Assuming your API returns the user's email
            print(f"Extracted Token: {token}")
            print(f"Extracted Email: {email}")
            
            if token:
                return {"email": email, "token": token}
            else:
                print("Token not found in API response.")
                return None
        else:
            print(f"Login failed with status code: {response.status_code}")
            return None
    except Exception as e:
        print(f"Error during login API call: {e}")
        raise requests.RequestException(f"Error during login: {e}")

def logout():
    """
    Log out the current user by clearing session state.
    """
    # Note: If your Django backend requires a logout API call, add it here
    # For now, we just clear the session state in streamlit_app.py
    pass

def is_authenticated():
    """
    Check if the user is authenticated by checking session state.
    
    Returns:
        bool: True if authenticated, False otherwise.
    """
    # Note: If your Django backend provides an endpoint to check authentication status,
    # you can make an API call here using the token from st.session_state["token"]
    return st.session_state.get("authenticated", False)