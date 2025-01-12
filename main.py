import json
import random
import string
import time

import jwt
from fastapi import FastAPI, HTTPException, APIRouter
import bcrypt
import mysql.connector
from fastapi.params import Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jwt import PyJWTError
from mysql.connector import Error
from datetime import datetime, timedelta

from starlette.middleware.cors import CORSMiddleware

from Models.OTP import RequestOTP, VerifyOTP
from Models.User import UserRegistration, UserLogin, UserDetails, UserSettingsUpdate

ACCESS_TOKEN_SECRET = "your_access_token_secret"
REFRESH_TOKEN_SECRET = "your_refresh_token_secret"
ALGORITHM = "HS256"

OTP_EXPIRATION_TIME = 300

# Database connection details
db_config = {
    'host': 'localhost',  # Replace with your MySQL host
    'user': 'root',  # Replace with your MySQL username
    'password': '75BCD1532!a',  # Replace with your MySQL password
    'database': 'WeatherRunning'  # Replace with your database name
}

router = APIRouter(
    prefix='/auth',
    tags=['auth']
)

origins = [
    "https://localhost:5173",
    "http://localhost:3000",
    "http://localhost:5173",
]

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# TODO: change this to redis with ttl
otp_store = {}


def generate_otp(length=6):
    """Generate a random OTP with the specified length."""
    return ''.join(random.choices(string.digits, k=length))


security = HTTPBearer()  # Use HTTPBearer to extract the token


def jwt_validator(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    """
    Dependency to validate JWT tokens.
    """
    token = credentials.credentials  # Extract the token
    payload = validate_jwt_token(token)  # Use your validate_jwt_token function
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token.")
    return payload  # Optionally return payload for use in the endpoint


# Function to validate the token
def validate_jwt_token(token: str) -> bool:
    try:
        # Decode the token and verify the signature and expiration
        payload = jwt.decode(token, ACCESS_TOKEN_SECRET, algorithms=[ALGORITHM])

        # Check if the token is expired (handled automatically by jwt.decode)
        if datetime.utcnow() > datetime.fromtimestamp(payload["exp"]):
            raise ValueError("Token has expired.")

        # Token is valid, return the payload
        return payload
    except PyJWTError as e:
        # Handle decoding errors or invalid token formats
        print(f"JWT validation error: {str(e)}")
        return None
    except Exception as e:
        # Handle other potential issues
        print(f"Unexpected error during JWT validation: {str(e)}")
        return None


def create_jwt_token(user_id: int, email: str, secret_key: str, expiry: timedelta) -> str:
    """
    Generate a JWT token for the authenticated user.
    """
    payload = {
        "sub": user_id,
        "email": email,
        "exp": datetime.utcnow() + expiry,
        "iat": datetime.utcnow(),
    }
    token = jwt.encode(payload, secret_key, algorithm=ALGORITHM)
    return token


def hash_password(password: str) -> str:
    """
    Hash a password using bcrypt.
    """
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')


@app.put("/update_user_details")
async def update_user_details(user: UserSettingsUpdate, payload: dict = Depends(jwt_validator)):
    try:
        # Connect to the database
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()
        update_query = """
        UPDATE Users
        SET
        name = %s,
        country = %s,
        city = %s,
        minTemperature = %s,
        maxTemperature = %s,
        weekDaysRunning = %s,
        noteByEmail = %s,
        noteByWhatsapp = %s,
        noteBySMS = %s
        WHERE
        email = %s;"""

        # Execute the query
        cursor.execute(
            update_query,
            (
                user.name,
                user.country,
                user.city,
                user.minTemperature,
                user.maxTemperature,
                user.weekDaysRunning,
                user.noteByEmail,
                user.noteByWhatsapp,
                user.noteBySMS,
                user.email
            ),
        )

        # Commit the transaction
        connection.commit()

        return {"message": "User details updated successfully!"}

    except Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

    finally:
        # Close the connection
        if connection.is_connected():
            cursor.close()
            connection.close()


@app.get("/get_user_details")
async def get_user_details(payload: dict = Depends(jwt_validator)):
    try:
        email = payload["email"]
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)
        query = "SELECT * FROM Users WHERE email = %s"
        cursor.execute(query, (email,))
        res = cursor.fetchone()
        if not res:
            raise HTTPException(status_code=404, detail="User not found")

        return {
                "name": res["name"],
                "id": res["id"],
                "email": res["email"],
                "phoneNumber": res["phoneNumber"],
                "city": res["city"],
                "country": res["country"],
                "minTemperature": res["minTemperature"],
                "maxTemperature": res["maxTemperature"],
                "weekDaysRunning": res["weekDaysRunning"],
                "noteByEmail": res["noteByEmail"],
                "noteByWhatsapp": res["noteByWhatsapp"],
                "noteBySMS": res["noteBySMS"]
        }

    except mysql.connector.Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

    finally:
        # Close the connection
        if connection.is_connected():
            cursor.close()
            connection.close()


@app.post("/verify-otp")
async def verify_otp_for_user(request: VerifyOTP):
    phone_number = request.phone_number
    user_otp = request.otp

    if phone_number not in otp_store:
        raise HTTPException(status_code=404, detail="OTP not found for this phone number")

    stored_otp_data = otp_store[phone_number]

    if time.time() > stored_otp_data["expires_at"]:
        del otp_store[phone_number]
        raise HTTPException(status_code=401, detail="OTP has expired")

    if user_otp != stored_otp_data["otp"]:
        raise HTTPException(status_code=401, detail="Invalid OTP")

    del otp_store[phone_number]

    return {"message": "OTP verified successfully"}


@app.post("/request-otp")
async def request_otp_for_user(request: RequestOTP):
    phone_number = request.phone_number

    # Generate a 6-digit OTP
    otp = generate_otp()

    # TODO: in future change this to redis
    # Store OTP in memory with an expiration time
    otp_store[phone_number] = {
        "otp": otp,
        "expires_at": time.time() + OTP_EXPIRATION_TIME  # Current time + expiration time
    }

    # In a real-world scenario, you would send the OTP to the user's phone number here.
    # For this example, we'll return it in the response (DO NOT do this in production!)
    return {"message": "OTP generated successfully", "otp": otp}


@app.post('/refresh')
async def refresh(payload: dict):
    refresh_token = payload.get("refresh_token")

    if not refresh_token:
        raise HTTPException(status_code=400, detail="Refresh token is required")

    try:
        # Decode refresh token
        payload = jwt.decode(refresh_token, REFRESH_TOKEN_SECRET, algorithms=[ALGORITHM])
        email = payload["email"]
        id = payload["sub"]

        if datetime.utcnow() > datetime.fromtimestamp(payload["exp"]):
            raise HTTPException(status_code=403, detail="Refresh token has expired")

        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)
        query = "SELECT * FROM Users WHERE email = %s"
        cursor.execute(query, (email,))
        res = cursor.fetchone()
        if not res:
            raise HTTPException(status_code=401, detail="Invalid email or password")
        # Verify token is still valid (exists in DB)
        if refresh_token != res["refresh_token"]:
            raise HTTPException(status_code=403, detail="Invalid or revoked refresh token")

        # Generate a new access token
        access_token = create_jwt_token(user_id=id, email=email, secret_key=ACCESS_TOKEN_SECRET,
                                        expiry=timedelta(hours=1))
        new_refresh_token = create_jwt_token(user_id=id, email=email, secret_key=REFRESH_TOKEN_SECRET,
                                             expiry=timedelta(days=1))

        update_query = """
        UPDATE Users
        SET
        refresh_token = %s,
        token_updated_at = %s
        WHERE
        email = %s;"""

        updated_at = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        # Execute the query
        cursor.execute(
            update_query,
            (
                new_refresh_token,
                updated_at,
                email,
            ),
        )

        # Commit the transaction
        connection.commit()

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer"
        }

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=403, detail="Refresh token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=403, detail="Invalid token")


@app.post("/login")
async def login(user_credentials: UserLogin):
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)
        query = "SELECT * FROM Users WHERE email = %s"
        cursor.execute(query, (user_credentials.email,))
        res = cursor.fetchone()
        if not res:
            raise HTTPException(status_code=401, detail="Invalid email or password")

        stored_hashed_password = res["password"]
        if not bcrypt.checkpw(user_credentials.password.encode('utf-8'), stored_hashed_password.encode('utf-8')):
            raise HTTPException(status_code=401, detail="Invalid email or password")

        access_token = create_jwt_token(user_id=res["id"], email=res["email"], secret_key=ACCESS_TOKEN_SECRET,
                                        expiry=timedelta(hours=1))
        refresh_token = create_jwt_token(user_id=res["id"], email=res["email"], secret_key=REFRESH_TOKEN_SECRET,
                                         expiry=timedelta(days=1))

        update_query = """
        UPDATE Users
        SET
        refresh_token = %s,
        token_updated_at = %s
        WHERE
        email = %s;"""

        updated_at = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        # Execute the query
        cursor.execute(
            update_query,
            (
                refresh_token,
                updated_at,
                user_credentials.email,
            ),
        )

        # Commit the transaction
        connection.commit()

        return {
            "message": "Login successful",
            "user": {
                "name": res["name"],
                "id": res["id"],
                "email": res["email"],
                "phoneNumber": res["phoneNumber"],
                "city": res["city"],
            },
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer"
        }

    except mysql.connector.Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

    finally:
        # Close the connection
        if connection.is_connected():
            cursor.close()
            connection.close()


@app.post("/register")
async def register_user(user: UserRegistration):
    try:
        # Connect to the database
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()

        query = "SELECT * FROM Users WHERE email = %s"
        cursor.execute(query, (user.email,))
        res = cursor.fetchone()
        if res:
            raise HTTPException(status_code=400, detail="Email already exist")

        # Hash the password
        hashed_password = hash_password(user.password)

        # SQL query to insert a new user
        insert_query = """
        INSERT INTO Users (
            name, phoneNumber, email, password, country, city, 
            minTemperature, maxTemperature, 
            weekDaysRunning, noteByEmail, noteByWhatsapp, noteBySMS
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """

        # Execute the query
        cursor.execute(
            insert_query,
            (
                user.name,
                user.phoneNumber,
                user.email,
                hashed_password,  # Store the hashed password
                user.country,
                user.city,
                user.minTemperature,
                user.maxTemperature,
                user.weekDaysRunning,
                user.noteByEmail,
                user.noteByWhatsapp,
                user.noteBySMS,
            ),
        )

        # Commit the transaction
        connection.commit()

        return {"message": "User registered successfully!"}

    except Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

    finally:
        # Close the connection
        if connection.is_connected():
            cursor.close()
            connection.close()


app.include_router(router)

# try:
#     # Connect to the database
#     connection = mysql.connector.connect(**db_config)
#
#     # Create a cursor object
#     cursor = connection.cursor(dictionary=True)  # Use dictionary=True for row results as dictionaries
#
#     # Query to select all users
#     query = "SELECT * FROM Users"
#
#     # Execute the query
#     cursor.execute(query)
#
#     # Fetch all rows
#     users = cursor.fetchall()
#
#     # Print user details
#     for user in users:
#         print(f"ID: {user['id']}, Name: {user['name']}, Email: {user['email']}")
#         print(f"Phone: {user['phoneNumber']}, Country: {user['country']}, City: {user['city']}")
#         print(
#             f"WeekDaysRunning: {user['weekDaysRunning']}, Notifications: Email={user['noteByEmail']}, WhatsApp={user['noteByWhatsapp']}, SMS={user['noteBySMS']}")
#         print("---------------------------------------------------------")
#
# except mysql.connector.Error as err:
#     print(f"Error: {err}")
#
# finally:
#     # Close the database connection
#     if connection.is_connected():
#         cursor.close()
#         connection.close()
#         print("Database connection closed.")
