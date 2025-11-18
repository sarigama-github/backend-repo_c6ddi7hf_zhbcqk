"""
Database Schemas for Bartender Academy

Each Pydantic model below maps to a MongoDB collection using the lowercase of the
class name as collection name.

Collections:
- user
- drink
- theorysection
- certificate
- sharelink

"""
from __future__ import annotations
from typing import List, Optional, Literal
from pydantic import BaseModel, Field, EmailStr


class User(BaseModel):
    """
    Admin users who can manage content
    Collection: user
    """
    name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Unique email address")
    password_hash: str = Field(..., description="BCrypt password hash")
    is_admin: bool = Field(True, description="Admin privileges")
    language: Literal["en", "it"] = Field("en", description="Preferred language")


class DrinkIngredient(BaseModel):
    name_it: str = Field(..., description="Ingredient name (Italian)")
    name_en: str = Field(..., description="Ingredient name (English)")
    quantity: str = Field(..., description="Measurement (e.g., 45 ml, 1 dash)")


class Drink(BaseModel):
    """Cocktail / drink recipe
    Collection: drink
    """
    name_it: str = Field(..., description="Nome del drink (Italiano)")
    name_en: str = Field(..., description="Drink name (English)")
    category: Optional[str] = Field(None, description="Category: Classic, Contemporary, etc.")
    method: Optional[str] = Field(None, description="Build, Stir, Shake, Blend, Throwing, etc.")
    base_spirit: Optional[str] = Field(None, description="Primary spirit")
    glassware: Optional[str] = Field(None, description="Glass type")
    garnish: Optional[str] = Field(None, description="Garnish details")
    description_it: Optional[str] = Field(None, description="Descrizione (IT)")
    description_en: Optional[str] = Field(None, description="Description (EN)")
    ingredients: List[DrinkIngredient] = Field(default_factory=list)
    image_url: Optional[str] = Field(None, description="Image URL or path")


class TheorySection(BaseModel):
    """
    Theory content sections in both languages.
    Collection: theorysection
    """
    slug: str = Field(..., description="Unique slug (e.g., glassware, tools, mixing-methods)")
    title_it: str = Field(...)
    title_en: str = Field(...)
    content_it: str = Field(..., description="Rich text/markdown allowed")
    content_en: str = Field(..., description="Rich text/markdown allowed")
    order: int = Field(0, description="Display order")


class Certificate(BaseModel):
    """Certificates uploaded by admin
    Collection: certificate
    """
    title_it: str
    title_en: str
    description_it: Optional[str] = None
    description_en: Optional[str] = None
    date: Optional[str] = Field(None, description="ISO date string")
    kind: Literal["course", "master"] = Field("course", description="Type of certificate")
    image_url: Optional[str] = Field(None, description="Path/URL to certificate image")


class ShareLink(BaseModel):
    """Secure shareable links for certificates
    Collection: sharelink
    """
    token: str = Field(..., description="Unguessable token")
    certificate_ids: List[str] = Field(default_factory=list, description="List of certificate _id strings")
    expires_at: Optional[str] = Field(None, description="ISO datetime for expiry")
    one_time: bool = Field(False, description="If true, link can be opened only once")
    used: bool = Field(False, description="Used status for one-time links")
    revoked: bool = Field(False, description="If true, link is invalid")
