from pydantic import BaseModel


class RequestOTP(BaseModel):
    phone_number: str


class VerifyOTP(BaseModel):
    phone_number: str
    otp: str
