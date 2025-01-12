from pydantic import BaseModel, EmailStr, Field


class UserDetails(BaseModel):
    name: str = Field(..., max_length=255)
    country: str = Field(..., max_length=100)
    city: str = Field(..., max_length=100)
    minTemperature: int = Field(default=15)
    maxTemperature: int = Field(default=25)
    weekDaysRunning: int = Field(default=1111111)  # Stored as a 7-digit decimal number
    noteByEmail: bool = Field(default=False)
    noteByWhatsapp: bool = Field(default=False)
    noteBySMS: bool = Field(default=True)


class UserSettingsUpdate(UserDetails):
    email: EmailStr


class UserRegistration(UserDetails):
    phoneNumber: str = Field(..., max_length=20)
    email: EmailStr
    password: str = Field(..., min_length=6)


class UserLogin(BaseModel):
    email: str
    password: str
